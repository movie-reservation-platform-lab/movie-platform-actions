/** Generate canonical v3 evidence from one complete report and one fresh policy decision. */
import { appendFileSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { publicationContext, requireDigest } from "./profile.mjs";
import { evaluateApprovedReport, renderApprovedSummary } from "./approved-evaluation.mjs";
import { readDocument, requireRuntime, sha256, writeJson } from "./runtime-files.mjs";
/**
 * Capture evidence, acquire/evaluate once, retain diagnostics, then write only a nonblocking candidate.
 * The transport and decision clock are test seams, never action or environment inputs.
 * The composite must verify image provenance before this writer and attest the four files afterward.
 */
export async function generateV3Evidence(env, readPolicyJson, decisionTime) {
    const context = readCandidateContext(env);
    const members = captureEvidenceMembers(context);
    const decision = await evaluateApprovedReport(members.report.bytes, context.image, context.profile.component, "immutable-ghcr", env.GH_TOKEN, readPolicyJson, decisionTime);
    // Rejected runs still retain every finding and its explanation; these diagnostics are not canonical evidence.
    writeJson(join(context.workspace, "security-evidence/vulnerability-policy-diagnostic.json"), { diagnosticOnly: true, ...decision }, 1024 * 1024, "Policy diagnostic");
    appendFileSync(context.summaryPath, renderApprovedSummary(decision, context.profile.artifact));
    requireRuntime(decision.evaluation.blockingCritical === 0, "Unapproved CRITICAL findings block canonical evidence; inspect the retained rejected diagnostics.");
    requireUnchangedMembers(context.workspace, members);
    const generatedAt = new Date().toISOString();
    requireRuntime(Date.parse(generatedAt) >= Date.parse(decision.evaluation.evaluatedAt), "Evaluation time is after evidence generation.");
    const candidate = createCandidateDocument(context, members, decision, generatedAt);
    writeJson(join(context.workspace, "security-evidence/component-candidate-evidence-v1alpha3.json"), candidate, 1024 * 1024, "V3 candidate");
}
/** Validate the canonical producer/run identity and the image provenance reference before reading files. */
function readCandidateContext(env) {
    const profile = publicationContext(env);
    const digest = requireDigest(env.CANDIDATE_DIGEST);
    requireRuntime(env.GITHUB_WORKSPACE && env.GITHUB_STEP_SUMMARY, "Publication workspace/summary is missing.");
    requireRuntime(env.CANDIDATE_REPOSITORY === profile.image, "Candidate repository does not match the publication profile.");
    const attestationId = env.ATTESTATION_ID;
    requireRuntime(typeof attestationId === "string" && /^[1-9][0-9]*$/.test(attestationId), "Invalid image provenance attestation ID.");
    const attestationUrl = `https://github.com/${profile.repository}/attestations/${attestationId}`;
    requireRuntime(env.ATTESTATION_URL === attestationUrl, "Image provenance attestation URL does not match its profile.");
    return {
        profile, digest, attestationId, attestationUrl,
        image: `${profile.image}@${digest}`,
        workspace: realpathSync(env.GITHUB_WORKSPACE),
        summaryPath: env.GITHUB_STEP_SUMMARY,
        // publicationContext already validated these runner fields and their numeric bounds.
        sourceRevision: env.GITHUB_SHA,
        runId: env.GITHUB_RUN_ID,
        runAttempt: Number(env.GITHUB_RUN_ATTEMPT),
    };
}
/** Retain original bytes and each downstream file limit for hashing and a later stability check. */
function captureEvidenceMembers(context) {
    const capture = (filename, maxBytes, label) => {
        const path = `security-evidence/${filename}`;
        return { path, maxBytes, label, bytes: readDocument(context.workspace, path, maxBytes, label) };
    };
    return {
        provenance: capture(context.profile.provenance, 4 * 1024 * 1024, "Provenance bundle"),
        sbom: capture(context.profile.sbom, 16 * 1024 * 1024, "SBOM"),
        report: capture(context.profile.vulnerabilities, 16 * 1024 * 1024, "Vulnerability report"),
    };
}
/** Files may change while network acquisition runs; never describe different bytes than will be signed. */
function requireUnchangedMembers(workspace, members) {
    for (const member of Object.values(members)) {
        const currentBytes = readDocument(workspace, member.path, member.maxBytes, member.label);
        requireRuntime(currentBytes.equals(member.bytes), "Evidence member changed during policy acquisition.");
    }
}
/** Assemble the unchanged v3 contract from validated context, captured bytes and the single decision. */
function createCandidateDocument(context, members, decision, generatedAt) {
    const { profile, digest, attestationId, attestationUrl } = context;
    return {
        apiVersion: "ci.movie-platform.dev/v1alpha3",
        kind: "ComponentCandidateEvidence",
        component: profile.component,
        source: {
            repository: profile.repository,
            revision: context.sourceRevision,
            ref: "refs/heads/main",
        },
        workflow: {
            path: profile.workflow,
            job: profile.jobName,
            runId: context.runId,
            runAttempt: context.runAttempt,
            url: `https://github.com/${profile.repository}/actions/runs/${context.runId}/attempts/${context.runAttempt}`,
        },
        candidate: {
            repository: profile.image,
            digest,
            platform: { os: "linux", architecture: "amd64" },
        },
        provenance: {
            subjectName: profile.image,
            subjectDigest: digest,
            predicateType: "https://slsa.dev/provenance/v1",
            attestationId,
            attestationUrl,
            bundle: { path: members.provenance.path, sha256: sha256(members.provenance.bytes), format: "sigstore-bundle-json" },
        },
        securityEvidence: {
            artifactName: profile.artifact,
            sbom: { path: members.sbom.path, sha256: sha256(members.sbom.bytes), format: "cyclonedx-json" },
            vulnerabilities: {
                path: members.report.path,
                sha256: decision.reportSha256,
                format: "trivy-json",
                subject: context.image,
                counts: decision.evaluation.counts,
            },
            vulnerabilityPolicy: decision,
        },
        generatedAt,
    };
}
