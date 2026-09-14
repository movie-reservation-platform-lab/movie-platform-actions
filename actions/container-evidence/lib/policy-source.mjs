/** One authenticated acquisition of fixed actions main; no caller-selected policy authority. */
import { createHash } from "node:crypto";
import { request } from "node:https";
import { performance } from "node:perf_hooks";
import { componentName, parseExemption, parseExemptions } from "./exemption-policy.mjs";
import { PolicyError, validateObject } from "./policy-values.mjs";
import { parseJson, requireRuntime, RuntimeError } from "./runtime-files.mjs";
export const policyRepository = "movie-reservation-platform-lab/movie-platform-actions";
const prefix = `/repos/${policyRepository}/git/`;
const metadataLimit = 1024 * 1024;
/** Fixed HTTPS authority with explicit credentials, no proxy/config or redirect fallback. */
export function githubPolicyReader(token) {
    requireRuntime(typeof token === "string" && /^[\x21-\x7e]{1,4096}$/.test(token), "Latest approval acquisition requires a GitHub token with read access to the actions repository.");
    return async (endpoint, limit, deadline) => {
        requireRuntime(endpoint.startsWith(prefix) && /^(ref\/heads\/main|(commits|trees|blobs)\/[a-f0-9]{40})$/.test(endpoint.slice(prefix.length)), "Unsupported policy endpoint.");
        const remaining = Math.floor(deadline - performance.now());
        requireRuntime(remaining > 0, "Approval acquisition exceeded its 120-second total limit.");
        const bytes = await new Promise((resolve, reject) => {
            const chunks = [];
            let size = 0;
            const req = request({
                hostname: "api.github.com", port: 443, path: endpoint, method: "GET",
                agent: false, rejectUnauthorized: true,
                headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "User-Agent": "movie-platform-actions", "X-GitHub-Api-Version": "2022-11-28" },
            }, (response) => {
                if (response.statusCode !== 200) {
                    fail(new RuntimeError("Unable to retrieve latest approved policy from GitHub; check repository read access and connectivity. No cached or empty fallback is allowed."));
                    return;
                }
                response.on("error", () => fail(new RuntimeError("Approval response was interrupted.")));
                response.on("data", (chunk) => {
                    size += chunk.length;
                    if (size > limit)
                        fail(new RuntimeError(`Approval response byte limit=${limit}, observed=${size}; inspect policy using the local scanning path.`));
                    else
                        chunks.push(chunk);
                });
                response.on("end", () => resolve(Buffer.concat(chunks)));
            });
            const fail = (error) => { reject(error); req.destroy(); };
            const timer = setTimeout(() => fail(new RuntimeError("Approval acquisition exceeded its 120-second total limit.")), remaining);
            req.on("error", (error) => reject(error instanceof RuntimeError ? error : new RuntimeError("Authenticated approval retrieval failed; no cached or empty fallback was used.")));
            req.on("close", () => clearTimeout(timer));
            req.end();
        });
        return parseJson(bytes);
    };
}
function gitSha(value) {
    requireRuntime(typeof value === "string" && /^[a-f0-9]{40}$/.test(value), "Policy Git identity is invalid.");
    return value;
}
/** Resolve main once, traverse complete trees, and bind each selected record to its blob. */
export async function acquirePolicy(componentInput, read) {
    const component = componentName(componentInput);
    const deadline = performance.now() + 120_000;
    const get = async (suffix, limit = metadataLimit) => validateObject(await read(prefix + suffix, limit, deadline));
    const tree = async (sha) => {
        const response = await get(`trees/${sha}`);
        requireRuntime(response.sha === sha && response.truncated === false && Array.isArray(response.tree), "Approval tree identity is wrong or listing is incomplete.");
        requireRuntime(response.tree.length <= 4096, `Approval tree entry limit=4096, observed=${response.tree.length}; inspect policy locally.`);
        const names = new Set();
        return response.tree.map((item) => {
            const entry = validateObject(item);
            const name = entry.path;
            requireRuntime(typeof name === "string" && name.length > 0 && name.length <= 255 && name !== "." && name !== ".." && !/[/\\\u0000-\u001f\u007f\ud800-\udfff]/.test(name) && !names.has(name), "Approval tree contains ambiguous or unsafe members.");
            names.add(name);
            return { ...entry, path: name };
        });
    };
    const child = (entries, name) => {
        const entry = entries.find((item) => item.path === name);
        if (!entry)
            return undefined;
        requireRuntime(entry.type === "tree" && entry.mode === "040000", "Policy directory must be a Git tree, not a link or submodule.");
        return gitSha(entry.sha);
    };
    const ref = await get("ref/heads/main");
    const target = validateObject(ref.object);
    requireRuntime(ref.ref === "refs/heads/main" && target.type === "commit", "Policy source must resolve approved main to one commit.");
    const revision = gitSha(target.sha);
    const commit = await get(`commits/${revision}`);
    requireRuntime(commit.sha === revision, "Policy commit identity mismatch.");
    const root = await tree(gitSha(validateObject(commit.tree).sha));
    const policyTree = child(root, "security-exemptions");
    requireRuntime(policyTree !== undefined, "Authoritative repository has no security-exemptions directory.");
    const selected = child(await tree(policyTree), component);
    const entries = selected === undefined ? [] : await tree(selected);
    requireRuntime(entries.length <= 128, `Approval record limit=128, observed=${entries.length}; inspect policy locally.`);
    const records = [];
    for (const entry of entries) {
        requireRuntime(entry.type === "blob" && entry.mode === "100644" && /^EX-[A-Za-z0-9][A-Za-z0-9-]{0,60}\.json$/.test(entry.path), "Selected approvals must be regular non-executable EX-ID.json files.");
        const size = entry.size;
        requireRuntime(typeof size === "number" && Number.isSafeInteger(size), "Approval raw record size metadata must be an integer.");
        requireRuntime(size > 0 && size <= 65536, `Approval ${component}/${entry.path} raw byte limit=65536, observed=${size}; inspect policy locally.`);
        const sha = gitSha(entry.sha);
        const blob = await get(`blobs/${sha}`, 128 * 1024);
        requireRuntime(blob.sha === sha && blob.size === size && blob.encoding === "base64" && typeof blob.content === "string", "Approval blob metadata disagrees with its tree entry.");
        const encoded = blob.content.replaceAll("\n", "");
        requireRuntime(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded), "Approval blob encoding is invalid.");
        const bytes = Buffer.from(encoded, "base64");
        requireRuntime(bytes.length === size && bytes.toString("base64") === encoded && createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex") === sha, "Approval blob bytes disagree with their immutable identity.");
        const record = validateObject(parseJson(bytes));
        requireRuntime(entry.path === `${String(record.id)}.json`, "Approval filename and record ID disagree.");
        try {
            const validated = parseExemption(record);
            requireRuntime(validated.component === component, `Approval ${component}/${entry.path} belongs to another component.`);
            records.push(validated);
        }
        catch (error) {
            if (error instanceof PolicyError) {
                const sizeDetail = error.code === "record-too-large" ? ` Canonical byte limit=16384, observed=${Buffer.byteLength(JSON.stringify(record))}.` : "";
                throw new RuntimeError(`Approval ${component}/${entry.path} is invalid (${error.code}).${sizeDetail} Inspect the central policy using the local scanning path.`);
            }
            throw error;
        }
    }
    let validated;
    try {
        validated = parseExemptions(records, component);
    }
    catch (error) {
        if (error instanceof PolicyError)
            throw new RuntimeError(`Approval set for ${component} at ${revision} is invalid (${error.code}); inspect the central policy using the local scanning path.`);
        throw error;
    }
    requireRuntime(performance.now() < deadline, "Approval acquisition exceeded its 120-second total limit.");
    return { revision, records: validated };
}
