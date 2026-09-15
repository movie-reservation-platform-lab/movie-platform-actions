import { test } from "node:test";
import assert from "node:assert/strict";
import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync,
  symlinkSync, truncateSync, writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const scripts = fileURLToPath(new URL("../actions/container-evidence/lib/", import.meta.url));
const secret = "PRIVATE_DIAGNOSTIC_SENTINEL";
const repository = "movie-reservation-platform-lab/movie-reservation-agent";
const image = `ghcr.io/${repository}@sha256:${"a".repeat(64)}`;
const entrypoints = ["evaluate-vulnerabilities.mjs", "write-candidate-evidence.mjs"];

/** A valid legacy publication, with every runner input visible and no inherited secrets. */
function fixture(t) {
  const workspace = mkdtempSync(join(tmpdir(), "legacy-evidence-safety-"));
  t.after(() => rmSync(workspace, { recursive: true, force: true }));
  const evidenceDirectory = join(workspace, "security-evidence");
  mkdirSync(evidenceDirectory);
  const reportPath = join(evidenceDirectory, "reservation-agent-vulnerabilities.json");
  const documentPath = join(evidenceDirectory, "component-candidate-evidence-v1alpha2.json");
  const report = { SchemaVersion: 2, ArtifactType: "container_image", ArtifactName: image, Results: [] };
  const env = {
    EVIDENCE_VERSION: "v1alpha2",
    COMPONENT: "reservation-agent",
    GITHUB_WORKSPACE: workspace,
    GITHUB_REPOSITORY: repository,
    GITHUB_REF: "refs/heads/main",
    GITHUB_EVENT_NAME: "push",
    GITHUB_SERVER_URL: "https://github.com",
    GITHUB_JOB: "publish-image",
    GITHUB_SHA: "b".repeat(40),
    GITHUB_RUN_ID: "123",
    GITHUB_RUN_ATTEMPT: "1",
    GITHUB_OUTPUT: join(workspace, "output"),
    GITHUB_STEP_SUMMARY: join(workspace, "summary"),
    CANDIDATE_REPOSITORY: `ghcr.io/${repository}`,
    CANDIDATE_DIGEST: `sha256:${"a".repeat(64)}`,
    ATTESTATION_ID: "456",
    ATTESTATION_URL: `https://github.com/${repository}/attestations/456`,
    REPORT_PATH: reportPath,
    EXPECTED_IMAGE: image,
    SUBJECT_KIND: "immutable-ghcr",
    EVIDENCE_ARTIFACT_NAME: "reservation-agent-security-evidence-123-attempt-1",
  };
  writeFileSync(reportPath, JSON.stringify(report));
  writeFileSync(join(evidenceDirectory, "reservation-agent-provenance.json"), "{}");
  writeFileSync(join(evidenceDirectory, "reservation-agent.cdx.json"), "{}");
  return {
    workspace, evidenceDirectory, reportPath, documentPath, report, env,
    saveReport: () => writeFileSync(reportPath, JSON.stringify(report)),
    run: (entrypoint) => spawnSync(process.execPath, [join(scripts, entrypoint)], {
      env, encoding: "utf8", timeout: 5_000, maxBuffer: 64 * 1024,
    }),
  };
}

/** Refusal must finish by itself, redact private input, and create no success artifacts. */
function assertRejected(f, entrypoint, diagnostic) {
  const result = f.run(entrypoint);
  assert.equal(result.error, undefined, "entrypoint must finish without the test killing it");
  assert.equal(result.status, 1, result.stderr);
  assert.doesNotMatch(result.stdout + result.stderr, new RegExp(secret));
  assert.doesNotMatch(result.stderr, /\n\s+at /, "do not print raw exception stacks");
  if (diagnostic) assert.match(result.stderr, diagnostic);
  assert.equal(existsSync(f.env.GITHUB_OUTPUT), false, "no workflow outputs on invalid input");
  assert.equal(existsSync(f.env.GITHUB_STEP_SUMMARY), false, "no success summary on invalid input");
  assert.equal(existsSync(f.documentPath), false, "no canonical evidence on invalid input");
}

for (const entrypoint of entrypoints) {
  test(`${entrypoint}: still accepts a valid legacy report`, (t) => {
    const f = fixture(t);
    const result = f.run(entrypoint);
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr);
    if (entrypoint === "evaluate-vulnerabilities.mjs") {
      assert.equal(readFileSync(f.env.GITHUB_OUTPUT, "utf8"), "high-count=0\ncritical-count=0\npolicy-result=passed\n");
    } else {
      const document = JSON.parse(readFileSync(f.documentPath, "utf8"));
      assert.equal(document.apiVersion, "ci.movie-platform.dev/v1alpha2");
      assert.equal(document.securityEvidence.vulnerabilities.counts.critical, 0);
    }
  });

  test(`${entrypoint}: malformed JSON cannot disclose report text`, (t) => {
    const f = fixture(t);
    writeFileSync(f.reportPath, `{"${secret}": invalid}`);
    assertRejected(f, entrypoint, /report must be valid JSON/);
  });

  for (const field of ["ArtifactName", "ArtifactType", "SchemaVersion", "Severity"]) {
    test(`${entrypoint}: invalid ${field} cannot disclose its value`, (t) => {
      const f = fixture(t);
      if (field === "Severity") {
        f.report.Results = [{ Vulnerabilities: [{
          VulnerabilityID: "CVE-2026-0001", PkgName: "example", InstalledVersion: "1", Severity: secret,
        }] }];
      } else f.report[field] = secret;
      f.saveReport();
      assertRejected(f, entrypoint);
    });
  }

  for (const kind of ["symlink", "directory", "fifo", "oversized", "missing"]) {
    test(`${entrypoint}: ${kind} report is rejected promptly without evidence`, { skip: kind === "fifo" && process.platform === "win32" }, (t) => {
      const f = fixture(t);
      if (kind === "symlink") {
        const target = join(f.workspace, "report-target.json");
        renameSync(f.reportPath, target);
        symlinkSync(target, f.reportPath);
      } else if (kind === "oversized") {
        // Sparse file exercises the pre-read cap without allocating a large test fixture.
        truncateSync(f.reportPath, 64 * 1024 * 1024 + 1);
      } else {
        rmSync(f.reportPath);
        if (kind === "directory") mkdirSync(f.reportPath);
        if (kind === "fifo") {
          const created = spawnSync("mkfifo", [f.reportPath], { encoding: "utf8", timeout: 5_000 });
          assert.equal(created.status, 0, created.stderr);
        }
      }
      assertRejected(f, entrypoint);
    });
  }

  test(`${entrypoint}: missing workspace cannot disclose a private filesystem path`, (t) => {
    const f = fixture(t);
    f.env.GITHUB_WORKSPACE = join(f.workspace, secret);
    assertRejected(f, entrypoint, /file operation failed/);
  });
}

for (const variable of ["SUBJECT_KIND", "EXPECTED_IMAGE", "EVIDENCE_ARTIFACT_NAME"]) {
  test(`legacy evaluator: invalid ${variable} cannot disclose its value`, (t) => {
    const f = fixture(t);
    f.env[variable] = `${secret}\ninvalid`;
    assertRejected(f, "evaluate-vulnerabilities.mjs");
  });
}

test("legacy evaluator: output I/O failure cannot disclose its path", (t) => {
  const f = fixture(t);
  f.env.GITHUB_OUTPUT = join(f.workspace, secret, "missing-output");
  assertRejected(f, "evaluate-vulnerabilities.mjs", /file operation failed/);
});

for (const variable of ["COMPONENT", "GITHUB_REPOSITORY", "CANDIDATE_DIGEST", "ATTESTATION_URL"]) {
  test(`legacy emitter: invalid ${variable} cannot disclose its value`, (t) => {
    const f = fixture(t);
    f.env[variable] = `${secret}\ninvalid`;
    assertRejected(f, "write-candidate-evidence.mjs");
  });
}
