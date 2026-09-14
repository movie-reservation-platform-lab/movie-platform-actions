/** Acquire one authenticated policy snapshot from fixed actions main and immutable Git objects. */
import { createHash } from "node:crypto";
import { request } from "node:https";
import { performance } from "node:perf_hooks";
import { componentName, parseExemption, parseExemptions } from "./exemption-policy.mjs";
import { PolicyError, validateObject } from "./policy-values.mjs";
import { parseJson, requireRuntime, RuntimeError } from "./runtime-files.mjs";
export const policyRepository = "movie-reservation-platform-lab/movie-platform-actions";
const policyApiPrefix = `/repos/${policyRepository}/git/`;
const acquisitionTimeoutMs = 120_000;
const maxMetadataBytes = 1024 * 1024;
const maxRawRecordBytes = 64 * 1024;
const maxBlobResponseBytes = 128 * 1024;
const maxTreeEntries = 4096;
const maxSelectedRecords = 128;
/** Create an authenticated reader with fixed HTTPS authority and no proxy/config or redirect fallback. */
export function githubPolicyReader(token) {
    requireRuntime(typeof token === "string" && /^[\x21-\x7e]{1,4096}$/.test(token), "Latest approval acquisition requires a GitHub token with read access to the actions repository.");
    return async (endpoint, maxBytes, deadlineMs) => {
        const allowedObjectPath = /^(ref\/heads\/main|(commits|trees|blobs)\/[a-f0-9]{40})$/;
        requireRuntime(endpoint.startsWith(policyApiPrefix) && allowedObjectPath.test(endpoint.slice(policyApiPrefix.length)), "Unsupported policy endpoint.");
        const responseBytes = await readAuthenticatedResponse(endpoint, token, maxBytes, deadlineMs);
        return parseJson(responseBytes);
    };
}
/** Bound the whole HTTP request and its response bytes; never return an error response as policy. */
function readAuthenticatedResponse(endpoint, token, maxBytes, deadlineMs) {
    const remainingMs = Math.floor(deadlineMs - performance.now());
    requireRuntime(remainingMs > 0, "Approval acquisition exceeded its 120-second total limit.");
    return new Promise((resolve, reject) => {
        const responseChunks = [];
        let receivedBytes = 0;
        const httpRequest = request({
            hostname: "api.github.com",
            port: 443,
            path: endpoint,
            method: "GET",
            agent: false,
            rejectUnauthorized: true,
            headers: {
                Authorization: `Bearer ${token}`,
                Accept: "application/vnd.github+json",
                "User-Agent": "movie-platform-actions",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        }, (response) => {
            if (response.statusCode !== 200) {
                failRequest(new RuntimeError("Unable to retrieve latest approved policy from GitHub; check repository read access and connectivity. No cached or empty fallback is allowed."));
                return;
            }
            response.on("error", () => failRequest(new RuntimeError("Approval response was interrupted.")));
            response.on("data", (chunk) => {
                receivedBytes += chunk.length;
                if (receivedBytes > maxBytes) {
                    failRequest(new RuntimeError(`Approval response byte limit=${maxBytes}, observed=${receivedBytes}; inspect policy using the local scanning path.`));
                }
                else {
                    responseChunks.push(chunk);
                }
            });
            response.on("end", () => resolve(Buffer.concat(responseChunks)));
        });
        const failRequest = (error) => {
            reject(error);
            httpRequest.destroy();
        };
        const timeout = setTimeout(() => failRequest(new RuntimeError("Approval acquisition exceeded its 120-second total limit.")), remainingMs);
        httpRequest.on("error", (error) => reject(error instanceof RuntimeError
            ? error
            : new RuntimeError("Authenticated approval retrieval failed; no cached or empty fallback was used.")));
        httpRequest.on("close", () => clearTimeout(timeout));
        httpRequest.end();
    });
}
/** Accept only full immutable Git identities, never branches, URLs or caller paths. */
function requireGitSha(value) {
    requireRuntime(typeof value === "string" && /^[a-f0-9]{40}$/.test(value), "Policy Git identity is invalid.");
    return value;
}
/** Validate a complete nonrecursive tree before interpreting any missing child as absence. */
async function readCompleteTree(readGitObject, treeSha) {
    const treeResponse = await readGitObject(`trees/${treeSha}`);
    requireRuntime(treeResponse.sha === treeSha && treeResponse.truncated === false && Array.isArray(treeResponse.tree), "Approval tree identity is wrong or listing is incomplete.");
    requireRuntime(treeResponse.tree.length <= maxTreeEntries, `Approval tree entry limit=4096, observed=${treeResponse.tree.length}; inspect policy locally.`);
    const memberNames = new Set();
    return treeResponse.tree.map((untrustedEntry) => {
        const entry = validateObject(untrustedEntry);
        const memberName = entry.path;
        requireRuntime(typeof memberName === "string" && memberName.length > 0 && memberName.length <= 255 &&
            memberName !== "." && memberName !== ".." &&
            !/[/\\\u0000-\u001f\u007f\ud800-\udfff]/.test(memberName) && !memberNames.has(memberName), "Approval tree contains ambiguous or unsafe members.");
        memberNames.add(memberName);
        return { ...entry, path: memberName };
    });
}
/** Return a real directory's Git identity, or absence established by a previously checked tree. */
function findDirectorySha(entries, directoryName) {
    const entry = entries.find((member) => member.path === directoryName);
    if (!entry)
        return undefined;
    requireRuntime(entry.type === "tree" && entry.mode === "040000", "Policy directory must be a Git tree, not a link or submodule.");
    return requireGitSha(entry.sha);
}
/** Check base64 bytes against both tree size and Git blob identity before parsing approval JSON. */
function decodeVerifiedBlob(blob, expectedSha, expectedBytes) {
    requireRuntime(blob.sha === expectedSha && blob.size === expectedBytes && blob.encoding === "base64" && typeof blob.content === "string", "Approval blob metadata disagrees with its tree entry.");
    const encodedContent = blob.content.replaceAll("\n", "");
    requireRuntime(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encodedContent), "Approval blob encoding is invalid.");
    const recordBytes = Buffer.from(encodedContent, "base64");
    // Git hashes the blob header plus raw bytes, unlike the contract's canonical record SHA-256.
    const actualBlobSha = createHash("sha1").update(`blob ${recordBytes.length}\0`).update(recordBytes).digest("hex");
    requireRuntime(recordBytes.length === expectedBytes && recordBytes.toString("base64") === encodedContent && actualBlobSha === expectedSha, "Approval blob bytes disagree with their immutable identity.");
    return recordBytes;
}
/** Read one regular EX-ID.json member and validate its filename, component and record semantics. */
async function readVerifiedApprovalRecord(component, entry, readGitObject) {
    requireRuntime(entry.type === "blob" && entry.mode === "100644" && /^EX-[A-Za-z0-9][A-Za-z0-9-]{0,60}\.json$/.test(entry.path), "Selected approvals must be regular non-executable EX-ID.json files.");
    const expectedBytes = entry.size;
    requireRuntime(typeof expectedBytes === "number" && Number.isSafeInteger(expectedBytes), "Approval raw record size metadata must be an integer.");
    requireRuntime(expectedBytes > 0 && expectedBytes <= maxRawRecordBytes, `Approval ${component}/${entry.path} raw byte limit=65536, observed=${expectedBytes}; inspect policy locally.`);
    const blobSha = requireGitSha(entry.sha);
    const blob = await readGitObject(`blobs/${blobSha}`, maxBlobResponseBytes);
    const record = validateObject(parseJson(decodeVerifiedBlob(blob, blobSha, expectedBytes)));
    requireRuntime(entry.path === `${String(record.id)}.json`, "Approval filename and record ID disagree.");
    try {
        const validatedRecord = parseExemption(record);
        requireRuntime(validatedRecord.component === component, `Approval ${component}/${entry.path} belongs to another component.`);
        return validatedRecord;
    }
    catch (error) {
        if (error instanceof PolicyError) {
            const sizeDetail = error.code === "record-too-large"
                ? ` Canonical byte limit=16384, observed=${Buffer.byteLength(JSON.stringify(record))}.`
                : "";
            throw new RuntimeError(`Approval ${component}/${entry.path} is invalid (${error.code}).${sizeDetail} Inspect the central policy using the local scanning path.`);
        }
        throw error;
    }
}
/**
 * Resolve approved main once and acquire only this component's immutable records.
 * A missing component in a complete tree means no approvals. A missing policy root
 * is a repository-layout failure, never permission to substitute empty policy.
 * Expired records remain in the snapshot; time eligibility belongs to evaluation.
 */
export async function acquirePolicy(componentInput, readPolicyJson) {
    const component = componentName(componentInput);
    const deadlineMs = performance.now() + acquisitionTimeoutMs;
    const readGitObject = async (objectPath, maxBytes = maxMetadataBytes) => validateObject(await readPolicyJson(policyApiPrefix + objectPath, maxBytes, deadlineMs));
    const mainReference = await readGitObject("ref/heads/main");
    const referenceTarget = validateObject(mainReference.object);
    requireRuntime(mainReference.ref === "refs/heads/main" && referenceTarget.type === "commit", "Policy source must resolve approved main to one commit.");
    const revision = requireGitSha(referenceTarget.sha);
    const commit = await readGitObject(`commits/${revision}`);
    requireRuntime(commit.sha === revision, "Policy commit identity mismatch.");
    const rootTreeSha = requireGitSha(validateObject(commit.tree).sha);
    const rootEntries = await readCompleteTree(readGitObject, rootTreeSha);
    const policyDirectorySha = findDirectorySha(rootEntries, "security-exemptions");
    requireRuntime(policyDirectorySha !== undefined, "Authoritative repository has no security-exemptions directory.");
    const policyEntries = await readCompleteTree(readGitObject, policyDirectorySha);
    const componentDirectorySha = findDirectorySha(policyEntries, component);
    const selectedEntries = componentDirectorySha === undefined
        ? []
        : await readCompleteTree(readGitObject, componentDirectorySha);
    requireRuntime(selectedEntries.length <= maxSelectedRecords, `Approval record limit=128, observed=${selectedEntries.length}; inspect policy locally.`);
    const loadedRecords = [];
    for (const entry of selectedEntries) {
        loadedRecords.push(await readVerifiedApprovalRecord(component, entry, readGitObject));
    }
    // Individual validity is insufficient: duplicate IDs or conflicting scopes invalidate the set.
    let validatedRecords;
    try {
        validatedRecords = parseExemptions(loadedRecords, component);
    }
    catch (error) {
        if (error instanceof PolicyError)
            throw new RuntimeError(`Approval set for ${component} at ${revision} is invalid (${error.code}); inspect the central policy using the local scanning path.`);
        throw error;
    }
    requireRuntime(performance.now() < deadlineMs, "Approval acquisition exceeded its 120-second total limit.");
    return { revision, records: validatedRecords };
}
