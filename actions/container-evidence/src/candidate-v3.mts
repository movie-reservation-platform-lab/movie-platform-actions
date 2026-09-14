/** Generate canonical v3 evidence from one complete report and one fresh policy decision. */
import { appendFileSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { publicationContext, requireDigest } from "./profile.mjs";
import { evaluateApprovedReport, renderApprovedSummary } from "./approved-evaluation.mjs";
import type { PolicyReader } from "./policy-source.mjs";
import { readDocument, requireRuntime, sha256, writeJson } from "./runtime-files.mjs";

/** Injectable transport/time are test seams, never environment or action inputs. */
export async function generateV3Evidence(env: NodeJS.ProcessEnv, read?: PolicyReader, now?: () => string): Promise<void> {
  const profile = publicationContext(env);
  const digest = requireDigest(env.CANDIDATE_DIGEST)!;
  requireRuntime(env.GITHUB_WORKSPACE && env.GITHUB_STEP_SUMMARY, "Publication workspace/summary is missing.");
  requireRuntime(env.CANDIDATE_REPOSITORY === profile.image, "Candidate repository does not match the publication profile.");
  const attestationId = env.ATTESTATION_ID;
  requireRuntime(typeof attestationId === "string" && /^[1-9][0-9]*$/.test(attestationId), "Invalid image provenance attestation ID.");
  const attestationUrl = `https://github.com/${profile.repository}/attestations/${attestationId}`;
  requireRuntime(env.ATTESTATION_URL === attestationUrl, "Image provenance attestation URL does not match its profile.");
  const workspace = realpathSync(env.GITHUB_WORKSPACE);
  const image = `${profile.image}@${digest}`;
  const provenancePath = `security-evidence/${profile.provenance}`;
  const sbomPath = `security-evidence/${profile.sbom}`;
  const reportPath = `security-evidence/${profile.vulnerabilities}`;
  const provenance = readDocument(workspace, provenancePath, 4 * 1024 * 1024, "Provenance bundle");
  const sbom = readDocument(workspace, sbomPath, 16 * 1024 * 1024, "SBOM");
  const report = readDocument(workspace, reportPath, 16 * 1024 * 1024, "Vulnerability report");
  const decision = await evaluateApprovedReport(report, image, profile.component, "immutable-ghcr", env.GH_TOKEN, read, now);
  writeJson(join(workspace, "security-evidence/vulnerability-policy-diagnostic.json"), { diagnosticOnly: true, ...decision }, 1024 * 1024, "Policy diagnostic");
  appendFileSync(env.GITHUB_STEP_SUMMARY, renderApprovedSummary(decision, profile.artifact));
  requireRuntime(decision.evaluation.blockingCritical === 0, "Unapproved CRITICAL findings block canonical evidence; inspect the retained rejected diagnostics.");
  // Recheck retained member bytes before binding them into the document for signing.
  for (const [path, bytes, limit, label] of [
    [provenancePath, provenance, 4 * 1024 * 1024, "Provenance bundle"],
    [sbomPath, sbom, 16 * 1024 * 1024, "SBOM"],
    [reportPath, report, 16 * 1024 * 1024, "Vulnerability report"],
  ] as const) {
    requireRuntime(readDocument(workspace, path, limit, label).equals(bytes), "Evidence member changed during policy acquisition.");
  }
  const evidence = {
    apiVersion: "ci.movie-platform.dev/v1alpha3", kind: "ComponentCandidateEvidence", component: profile.component,
    source: { repository: profile.repository, revision: env.GITHUB_SHA, ref: "refs/heads/main" },
    workflow: { path: profile.workflow, job: profile.jobName, runId: env.GITHUB_RUN_ID,
      runAttempt: Number(env.GITHUB_RUN_ATTEMPT), url: `https://github.com/${profile.repository}/actions/runs/${env.GITHUB_RUN_ID}/attempts/${env.GITHUB_RUN_ATTEMPT}` },
    candidate: { repository: profile.image, digest, platform: { os: "linux", architecture: "amd64" } },
    provenance: { subjectName: profile.image, subjectDigest: digest, predicateType: "https://slsa.dev/provenance/v1",
      attestationId, attestationUrl, bundle: { path: provenancePath, sha256: sha256(provenance), format: "sigstore-bundle-json" } },
    securityEvidence: { artifactName: profile.artifact,
      sbom: { path: sbomPath, sha256: sha256(sbom), format: "cyclonedx-json" },
      vulnerabilities: { path: reportPath, sha256: decision.reportSha256, format: "trivy-json", subject: image, counts: decision.evaluation.counts },
      vulnerabilityPolicy: decision },
    generatedAt: new Date().toISOString(),
  };
  requireRuntime(Date.parse(evidence.generatedAt) >= Date.parse(decision.evaluation.evaluatedAt), "Evaluation time is after evidence generation.");
  writeJson(join(workspace, "security-evidence/component-candidate-evidence-v1alpha3.json"), evidence, 1024 * 1024, "V3 candidate");
}
