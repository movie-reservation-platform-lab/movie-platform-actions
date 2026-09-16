/**
 * Writes the candidate evidence JSON with the image and build identity,
 * vulnerability counts, and hashes of the provenance bundle, SBOM, and scan report.
 * Dispatches v1alpha2 and v1alpha3 evidence generation. v1alpha2 rejects every
 * CRITICAL finding; v1alpha3 rejects unapproved CRITICAL findings. Both versions
 * refuse to overwrite an existing evidence document.
 */
import { createHash } from "node:crypto";
import { readFileSync, realpathSync, writeFileSync, lstatSync } from "node:fs";
import { isAbsolute, join, relative, resolve } from "node:path";

import { publicationContext } from "./profile.mjs";
import { readDocument, RuntimeError } from "./runtime-files.mjs";

// Profile errors are author-controlled, but keep this entrypoint's diagnostics
// independent of arbitrary exceptions and avoid printing an uncaught stack.
let profile: ReturnType<typeof publicationContext>;
try { profile = publicationContext(process.env); }
catch {
  console.error("Unable to emit candidate evidence: Invalid canonical publication context.");
  process.exit(1);
}
const sourceRepository = profile.repository;
if (profile.component === "reservation-service" && process.env.EVIDENCE_VERSION !== "v1alpha3") {
  console.error("Reservation-service requires explicit v1alpha3 evidence.");
  process.exit(1);
}
const candidateRepository = `ghcr.io/${sourceRepository}`;
const sourceRef = "refs/heads/main";
const githubServerUrl = "https://github.com";
const evidenceDocumentPath =
  "security-evidence/component-candidate-evidence-v1alpha2.json";
const provenanceBundlePath = `security-evidence/${profile.provenance}`;
const sbomPath = `security-evidence/${profile.sbom}`;
const vulnerabilityReportPath = `security-evidence/${profile.vulnerabilities}`;

type VulnerabilityCounts = {
  unknown: number;
  low: number;
  medium: number;
  high: number;
  critical: number;
};

if (process.env.EVIDENCE_VERSION === "v1alpha3") {
  const { generateV3Evidence } = await import("./candidate-v3.mjs");
  const { safeFailure } = await import("./runtime-files.mjs");
  try { await generateV3Evidence(process.env); }
  catch (error) { console.error(safeFailure(error)); process.exitCode = 1; }
} else if (process.env.EVIDENCE_VERSION && process.env.EVIDENCE_VERSION !== "v1alpha2") {
  console.error("Unsupported evidence version.");
  process.exitCode = 1;
} else try {
  const workspace = realpathSync(
    requireEnvironmentVariable("GITHUB_WORKSPACE"),
  );
  const sourceRevision = requireEnvironmentVariable("GITHUB_SHA");
  const runId = requireEnvironmentVariable("GITHUB_RUN_ID");
  const runAttempt = parsePositiveInteger(
    requireEnvironmentVariable("GITHUB_RUN_ATTEMPT"),
    "GITHUB_RUN_ATTEMPT",
  );
  const candidateDigest = requireEnvironmentVariable("CANDIDATE_DIGEST");
  const attestationId = requireEnvironmentVariable("ATTESTATION_ID");
  const attestationUrl = requireEnvironmentVariable("ATTESTATION_URL");

  requireExactEnvironmentVariable("GITHUB_REPOSITORY", sourceRepository);
  requireExactEnvironmentVariable("GITHUB_REF", sourceRef);
  requireExactEnvironmentVariable("GITHUB_SERVER_URL", githubServerUrl);
  requireExactEnvironmentVariable("CANDIDATE_REPOSITORY", candidateRepository);
  validatePattern(
    "GITHUB_SHA",
    sourceRevision,
    /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/,
  );
  validatePattern("GITHUB_RUN_ID", runId, /^[1-9][0-9]*$/);
  validatePattern("CANDIDATE_DIGEST", candidateDigest, /^sha256:[0-9a-f]{64}$/);
  validatePattern("ATTESTATION_ID", attestationId, /^[1-9][0-9]*$/);

  const expectedAttestationUrl = `${githubServerUrl}/${sourceRepository}/attestations/${attestationId}`;
  if (attestationUrl !== expectedAttestationUrl) {
    throw new RuntimeError("ATTESTATION_URL must match the canonical attestation.");
  }

  const artifactName = profile.artifact;
  const immutableCandidate = `${candidateRepository}@${candidateDigest}`;
  const vulnerabilityCounts = readVulnerabilityCounts(
    workspace,
    immutableCandidate,
  );
  if (vulnerabilityCounts.critical > 0)
    throw new RuntimeError("CRITICAL findings block canonical evidence");
  const evidence = {
    apiVersion: "ci.movie-platform.dev/v1alpha2",
    kind: "ComponentCandidateEvidence",
    component: profile.component,
    source: {
      repository: sourceRepository,
      revision: sourceRevision,
      ref: sourceRef,
    },
    workflow: {
      path: ".github/workflows/ci.yml",
      job: profile.jobName,
      runId,
      runAttempt,
      url: `${githubServerUrl}/${sourceRepository}/actions/runs/${runId}/attempts/${runAttempt}`,
    },
    candidate: {
      repository: candidateRepository,
      digest: candidateDigest,
      platform: {
        os: "linux",
        architecture: "amd64",
      },
    },
    provenance: {
      subjectName: candidateRepository,
      subjectDigest: candidateDigest,
      predicateType: "https://slsa.dev/provenance/v1",
      attestationId,
      attestationUrl,
      bundle: {
        path: provenanceBundlePath,
        sha256: hashWorkspaceFile(workspace, provenanceBundlePath),
        format: "sigstore-bundle-json",
      },
    },
    securityEvidence: {
      artifactName,
      sbom: {
        path: sbomPath,
        sha256: hashWorkspaceFile(workspace, sbomPath),
        format: "cyclonedx-json",
      },
      vulnerabilities: {
        path: vulnerabilityReportPath,
        sha256: hashWorkspaceFile(workspace, vulnerabilityReportPath),
        format: "trivy-json",
        subject: immutableCandidate,
        counts: vulnerabilityCounts,
      },
    },
    generatedAt: new Date().toISOString(),
  };

  writeFileSync(
    join(workspace, evidenceDocumentPath),
    `${JSON.stringify(evidence, null, 2)}\n`,
    {
      encoding: "utf8",
      flag: "wx",
    },
  );
} catch (error) {
  const message = error instanceof RuntimeError ? error.message : "Evidence file operation failed.";

  console.error(`Unable to emit candidate evidence: ${message}`);
  process.exitCode = 1;
}

/** Reads a required runner setting, rejecting missing or empty values. */
function requireEnvironmentVariable(name: string): string {
  const value = process.env[name];

  if (value === undefined || value.length === 0) {
    throw new RuntimeError(`Required environment variable ${name} is missing.`);
  }

  return value;
}

/** Rejects a runner setting that differs from the expected publication identity. */
function requireExactEnvironmentVariable(name: string, expected: string): void {
  const value = requireEnvironmentVariable(name);

  if (value !== expected) {
    throw new RuntimeError(`${name} must match the canonical publication identity.`);
  }
}

/** Checks an input's format, naming the invalid setting without echoing its value. */
function validatePattern(name: string, value: string, pattern: RegExp): void {
  if (!pattern.test(value)) {
    throw new RuntimeError(`${name} has an unsupported value.`);
  }
}

/** Parses a positive decimal integer without leading zeros or loss of numeric precision. */
function parsePositiveInteger(value: string, name: string): number {
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new RuntimeError(`${name} must be a positive integer.`);
  }

  const parsed = Number(value);

  if (!Number.isSafeInteger(parsed)) {
    throw new RuntimeError(`${name} exceeds the supported integer range.`);
  }

  return parsed;
}

/**
 * Checks that the Trivy report describes the expected image and counts findings
 * by severity. Missing or null result lists count as no findings; invalid entries fail.
 */
function readVulnerabilityCounts(
  workspace: string,
  expectedImage: string,
): VulnerabilityCounts {
  const bytes = readDocument(workspace, vulnerabilityReportPath, 64 * 1024 * 1024, "Vulnerability report");
  let report: unknown;
  try { report = JSON.parse(bytes.toString("utf8")) as unknown; }
  catch { throw new RuntimeError("Vulnerability report must be valid JSON."); }

  if (
    !isRecord(report) ||
    report.SchemaVersion !== 2 ||
    report.ArtifactType !== "container_image"
  ) {
    throw new RuntimeError(
      "Vulnerability report is not a supported Trivy container report.",
    );
  }

  if (report.ArtifactName !== expectedImage) {
    throw new RuntimeError(
      "Vulnerability report subject does not match the candidate image.",
    );
  }

  const counts: VulnerabilityCounts = {
    unknown: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };
  const results = report.Results;

  if (results === undefined || results === null) {
    return counts;
  }

  if (!Array.isArray(results)) {
    throw new RuntimeError("Vulnerability report Results must be an array.");
  }

  for (const [resultIndex, result] of results.entries()) {
    if (!isRecord(result)) {
      throw new RuntimeError(
        `Vulnerability report result ${resultIndex} must be an object.`,
      );
    }

    const vulnerabilities = result.Vulnerabilities;
    if (vulnerabilities === undefined || vulnerabilities === null) {
      continue;
    }

    if (!Array.isArray(vulnerabilities)) {
      throw new RuntimeError(
        `Vulnerabilities at result ${resultIndex} must be an array.`,
      );
    }

    for (const [
      vulnerabilityIndex,
      vulnerability,
    ] of vulnerabilities.entries()) {
      if (
        !isRecord(vulnerability) ||
        typeof vulnerability.Severity !== "string"
      ) {
        throw new RuntimeError(
          `Vulnerability ${vulnerabilityIndex} at result ${resultIndex} has no valid Severity.`,
        );
      }

      const severity = vulnerability.Severity.toLowerCase();
      switch (severity) {
        case "unknown":
        case "low":
        case "medium":
        case "high":
        case "critical":
          counts[severity] += 1;
          break;
        default:
          throw new RuntimeError(
            `Vulnerability ${vulnerabilityIndex} at result ${resultIndex} has unsupported severity.`,
          );
      }
    }
  }

  return counts;
}

/** Hashes a checked evidence file, returning its digest with the sha256: prefix. */
function hashWorkspaceFile(workspace: string, relativePath: string): string {
  return `sha256:${createHash("sha256")
    .update(readFileSync(resolveWorkspaceFile(workspace, relativePath)))
    .digest("hex")}`;
}

/**
 * Resolves an evidence file within the workspace, rejecting files over 64 MiB,
 * non-regular files, and paths whose final component is a symlink.
 */
function resolveWorkspaceFile(workspace: string, relativePath: string): string {
  const requested = resolve(workspace, relativePath);
  if (
    !lstatSync(requested).isFile() ||
    lstatSync(requested).size > 64 * 1024 * 1024
  ) {
    throw new RuntimeError("Evidence must be a bounded regular file");
  }
  const path = realpathSync(requested);
  const pathWithinWorkspace = relative(workspace, path);

  if (
    pathWithinWorkspace === ".." ||
    pathWithinWorkspace.startsWith(
      `..${process.platform === "win32" ? "\\" : "/"}`,
    ) ||
    isAbsolute(pathWithinWorkspace)
  ) {
    throw new RuntimeError(
      "Evidence path must stay inside GITHUB_WORKSPACE.",
    );
  }

  return path;
}

/** Narrows a JSON value to an object with readable fields, excluding null and arrays. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
