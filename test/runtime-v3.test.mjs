import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, readdirSync, rmSync, existsSync, symlinkSync, truncateSync, linkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Ajv from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { generateV3Evidence } from "../actions/container-evidence/lib/candidate-v3.mjs";
import { evaluateApprovedReport, renderApprovedSummary } from "../actions/container-evidence/lib/approved-evaluation.mjs";
import { readDocument, sha256, writeJson } from "../actions/container-evidence/lib/runtime-files.mjs";
import { scanHosted, hostedScannerImage, hostedScannerArguments } from "../actions/container-evidence/lib/scan-v3.mjs";
import { scannerImage, scannerArguments } from "../local-tools/container-security/lib/trivy-runner.mjs";
import { baseline, policyFixture } from "./support/policy-fixture.mjs";

const ajv = new Ajv({ strict: false, allErrors: true });
addFormats(ajv);
for (const name of ["component-candidate-evidence-v1alpha2", "container-vulnerability-exemption-v1alpha1", "component-candidate-evidence-v1alpha3"]) {
  ajv.addSchema(JSON.parse(readFileSync(new URL(`../contracts/${name}.schema.json`, import.meta.url))));
}
const validate = ajv.getSchema("https://schemas.movie-platform.dev/ci/component-candidate-evidence-v1alpha3.schema.json");
const candidateName = "component-candidate-evidence-v1alpha3.json";

function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), "v3-runtime-test-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const evidence = join(directory, "security-evidence");
  mkdirSync(evidence);
  const env = { COMPONENT: baseline.component, GITHUB_REPOSITORY: "movie-reservation-platform-lab/movie-recommendation-mcp",
    GITHUB_REF: "refs/heads/main", GITHUB_EVENT_NAME: "push", GITHUB_SERVER_URL: "https://github.com", GITHUB_JOB: "publish-image",
    GITHUB_SHA: "b".repeat(40), GITHUB_RUN_ID: "123", GITHUB_RUN_ATTEMPT: "2", CANDIDATE_DIGEST: "sha256:" + "a".repeat(64),
    CANDIDATE_REPOSITORY: baseline.expectedImage.split("@")[0], ATTESTATION_ID: "456",
    ATTESTATION_URL: "https://github.com/movie-reservation-platform-lab/movie-recommendation-mcp/attestations/456",
    GITHUB_WORKSPACE: directory, GITHUB_STEP_SUMMARY: join(directory, "summary"), RUNNER_TEMP: directory,
    GITHUB_ACTOR: "fixture-user", GH_TOKEN: "TOKEN_SENTINEL", PATH: process.env.PATH };
  const report = structuredClone(baseline.report);
  const put = (filename, value) => writeFileSync(join(evidence, filename), JSON.stringify(value));
  put("recommendation-mcp-provenance.json", { dsseEnvelope: { payloadType: "application/vnd.in-toto+json" } });
  put("recommendation-mcp.cdx.json", { bomFormat: "CycloneDX", specVersion: "1.6", version: 1, metadata: { component: { type: "container", name: baseline.expectedImage } }, components: [] });
  put("recommendation-mcp-vulnerabilities.json", report);
  return { directory, evidence, env, report, put, candidate: () => JSON.parse(readFileSync(join(evidence, candidateName))) };
}

test("v3 writer preserves complete raw findings and binds approved decision into the four named files", async t => {
  const f = fixture(t);
  const policy = policyFixture();
  const before = readFileSync(join(f.evidence, "recommendation-mcp-vulnerabilities.json"));
  await generateV3Evidence(f.env, policy.read, () => baseline.now);
  const candidate = f.candidate();
  assert.equal(validate(candidate), true, JSON.stringify(validate.errors));
  const e = candidate.securityEvidence.vulnerabilityPolicy.evaluation;
  assert.equal(e.result, "passed-with-exemptions");
  assert.equal(e.counts.critical, 1);
  assert.equal(e.blockingCritical, 0);
  assert.equal(e.findings.length, 2);
  assert.equal(e.exemptions[0].record.rationale, baseline.records[0].rationale);
  assert.equal(candidate.securityEvidence.vulnerabilityPolicy.reportSha256, sha256(before));
  assert.deepEqual(readFileSync(join(f.evidence, "recommendation-mcp-vulnerabilities.json")), before);
  assert.equal(policy.calls.filter(call => call.endpoint.endsWith("ref/heads/main")).length, 1);
  assert.match(readFileSync(f.env.GITHUB_STEP_SUMMARY, "utf8"), /passed-with-exemptions/);
  assert.ok(!JSON.stringify(candidate).includes("TOKEN_SENTINEL"));
  await assert.rejects(generateV3Evidence(f.env, policyFixture().read, () => baseline.now), /EEXIST/);
});

test("mixed approved and unapproved CRITICALs retain diagnostics but never create a candidate", async t => {
  const f = fixture(t);
  f.report.Results[0].Vulnerabilities.push({ ...f.report.Results[0].Vulnerabilities[0], VulnerabilityID: "CVE-2099-99999" });
  f.put("recommendation-mcp-vulnerabilities.json", f.report);
  await assert.rejects(generateV3Evidence(f.env, policyFixture().read, () => baseline.now), /Unapproved CRITICAL/);
  assert.equal(existsSync(join(f.evidence, candidateName)), false);
  const diagnostic = JSON.parse(readFileSync(join(f.evidence, "vulnerability-policy-diagnostic.json")));
  assert.equal(diagnostic.diagnosticOnly, true);
  assert.equal(diagnostic.evaluation.findings.length, 3);
  assert.equal(diagnostic.evaluation.exemptions.length, 1);
  assert.equal(diagnostic.evaluation.blockingCritical, 1);
});

test("empty current policy permits only zero-CRITICAL reports", async t => {
  const f = fixture(t);
  f.report.Results[0].Vulnerabilities = f.report.Results[0].Vulnerabilities.slice(1);
  f.put("recommendation-mcp-vulnerabilities.json", f.report);
  await generateV3Evidence(f.env, policyFixture([]).read, () => baseline.now);
  assert.equal(f.candidate().securityEvidence.vulnerabilityPolicy.evaluation.result, "passed");
});

for (const scenario of ["withdrawn", "expired", "no-purl", "acquisition-failed", "report-subject", "wrong-platform", "changed-during-acquisition", "report-limit", "sbom-limit", "provenance-limit", "symlink", "hardlink", "wrong-attestation", "pr-context"]) {
  test(`v3 writer fails closed: ${scenario}`, async t => {
    const f = fixture(t);
    const policy = policyFixture(scenario === "withdrawn" ? [] : baseline.records);
    let read = policy.read;
    if (scenario === "no-purl") { delete f.report.Results[0].Vulnerabilities[0].PkgIdentifier; f.put("recommendation-mcp-vulnerabilities.json", f.report); }
    if (scenario === "acquisition-failed") read = async () => { throw new Error("PRIVATE_SENTINEL"); };
    if (scenario === "report-subject") { f.report.ArtifactName = "wrong:local"; f.put("recommendation-mcp-vulnerabilities.json", f.report); }
    if (scenario === "wrong-platform") { f.report.Metadata.ImageConfig.architecture = "arm64"; f.put("recommendation-mcp-vulnerabilities.json", f.report); }
    if (scenario === "changed-during-acquisition") read = async (...args) => { f.put("recommendation-mcp-vulnerabilities.json", {}); return policy.read(...args); };
    for (const [name, file, limit] of [["report", "recommendation-mcp-vulnerabilities.json", 16], ["sbom", "recommendation-mcp.cdx.json", 16], ["provenance", "recommendation-mcp-provenance.json", 4]]) {
      if (scenario === `${name}-limit`) truncateSync(join(f.evidence, file), limit * 1024 * 1024 + 1);
    }
    if (scenario === "symlink") { rmSync(join(f.evidence, "recommendation-mcp.cdx.json")); symlinkSync(join(f.evidence, "recommendation-mcp-provenance.json"), join(f.evidence, "recommendation-mcp.cdx.json")); }
    if (scenario === "hardlink") linkSync(join(f.evidence, "recommendation-mcp.cdx.json"), join(f.directory, "extra-link"));
    if (scenario === "wrong-attestation") f.env.ATTESTATION_URL = "https://evil.test";
    if (scenario === "pr-context") f.env.GITHUB_EVENT_NAME = "pull_request";
    await assert.rejects(generateV3Evidence(f.env, read, () => scenario === "expired" ? baseline.records[0].expiresAt : baseline.now));
    assert.equal(existsSync(join(f.evidence, candidateName)), false);
  });
}

test("local and hosted adapters produce equivalent decisions for the same findings and current approvals", async () => {
  const hosted = await evaluateApprovedReport(Buffer.from(JSON.stringify(baseline.report)), baseline.expectedImage, baseline.component, "immutable-ghcr", undefined, policyFixture().read, () => baseline.now);
  const report = { ...baseline.report, ArtifactName: "example:local" };
  const local = await evaluateApprovedReport(Buffer.from(JSON.stringify(report)), "example:local", baseline.component, "local", undefined, policyFixture().read, () => baseline.now);
  assert.deepEqual({ ...local.evaluation, subject: hosted.evaluation.subject }, hosted.evaluation);
  assert.notEqual(local.reportSha256, hosted.reportSha256);
});

test("summary escapes finding text and bounds presentation without truncating the decision", async () => {
  const report = structuredClone(baseline.report);
  report.Results[0].Vulnerabilities = Array.from({ length: 2000 }, () => ({ ...report.Results[0].Vulnerabilities[0], PkgName: "<b>" + "x".repeat(120), PkgIdentifier: undefined }));
  const decision = await evaluateApprovedReport(Buffer.from(JSON.stringify(report)), baseline.expectedImage, baseline.component, "immutable-ghcr", undefined, policyFixture([]).read, () => baseline.now);
  const summary = renderApprovedSummary(decision, "test");
  assert.ok(Buffer.byteLength(summary) < 256 * 1024);
  assert.doesNotMatch(summary, /<b>/);
  assert.match(summary, /all findings and decisions remain/);
  assert.equal(decision.evaluation.findings.length, 2000);
});

test("bounded file/output helpers reject containment escapes and actual serialized oversize", t => {
  const f = fixture(t);
  assert.throws(() => readDocument(f.evidence, "../summary", 100, "test"));
  const path = join(f.directory, "bounded.json");
  assert.throws(() => writeJson(path, { text: "é".repeat(10) }, 25, "V3 candidate"), /limit=25/);
  assert.equal(existsSync(path), false);
});

test("escaping many valid approval descriptions cannot turn a policy pass into an operational failure", async () => {
  const report = structuredClone(baseline.report);
  report.Results[0].Vulnerabilities = [];
  const records = Array.from({ length: 100 }, (_, index) => {
    const record = structuredClone(baseline.records[0]);
    record.id = `EX-SUMMARY-${index}`;
    record.vex["@id"] = `urn:movie-platform:exemption:${record.id}`;
    record.owner = "|".repeat(256);
    record.package.name = "|".repeat(256);
    record.vex.statements[0].vulnerability.name = `CVE-2099-${20000 + index}`;
    report.Results[0].Vulnerabilities.push({ ...baseline.report.Results[0].Vulnerabilities[0],
      VulnerabilityID: record.vex.statements[0].vulnerability.name, PkgName: record.package.name });
    return record;
  });
  const decision = await evaluateApprovedReport(Buffer.from(JSON.stringify(report)), baseline.expectedImage, baseline.component, "immutable-ghcr", undefined, policyFixture(records).read, () => baseline.now);
  assert.equal(decision.evaluation.result, "passed-with-exemptions");
  assert.equal(decision.evaluation.exemptions.length, 100);
  const summary = renderApprovedSummary(decision, "retained report and candidate JSON");
  assert.ok(Buffer.byteLength(summary) < 256 * 1024);
  assert.match(summary, /approval descriptions.*omitted.*complete retained JSON/);
  assert.equal(decision.evaluation.findings.length, 100);
});

test("hosted scanner is immutable and isolated from producer config, ignores, command overrides and credentials", t => {
  const f = fixture(t);
  Object.assign(f.env, { TRIVY_CMD: "evil", TRIVY_IGNORE_UNFIXED: "true", TRIVY_SKIP_FILES: "*", DOCKER_HOST: "tcp://evil", NODE_OPTIONS: "PRIVATE_SENTINEL" });
  const calls = [];
  const fake = (args, env, timeout, limit) => {
    const config = JSON.parse(readFileSync(join(env.DOCKER_CONFIG, "config.json")));
    assert.deepEqual(Object.keys(config.auths), ["ghcr.io"]);
    assert.equal(Buffer.from(config.auths["ghcr.io"].auth, "base64").toString(), "fixture-user:TOKEN_SENTINEL");
    calls.push({ args, env, timeout, limit });
    return Buffer.from("{}");
  };
  rmSync(join(f.evidence, "recommendation-mcp.cdx.json"));
  rmSync(join(f.evidence, "recommendation-mcp-vulnerabilities.json"));
  scanHosted(f.env, fake);
  assert.equal(calls.length, 2);
  for (const { args, env, timeout, limit } of calls) {
    assert.deepEqual(args.slice(0, 2), ["--host", "unix:///var/run/docker.sock"]);
    assert.equal(args.at(-1), baseline.expectedImage);
    assert.equal(args[args.indexOf("--config") + 1], "/dev/null");
    assert.equal(args[args.indexOf("--ignorefile") + 1], "/dev/null");
    assert.equal(args[args.indexOf("--volume") + 1], `${env.DOCKER_CONFIG}:/registry-auth:ro`);
    assert.equal(args.filter(arg => arg === "--volume").length, 1);
    assert.ok(args.includes("DOCKER_CONFIG=/registry-auth"));
    assert.ok(args.includes(hostedScannerImage));
    assert.ok(!args.includes("TOKEN_SENTINEL"));
    assert.equal(env.TRIVY_PASSWORD, undefined);
    assert.equal(env.GH_TOKEN, undefined);
    assert.equal(env.TRIVY_CMD, undefined);
    assert.equal(env.TRIVY_IGNORE_UNFIXED, undefined);
    assert.equal(env.NODE_OPTIONS, undefined);
    assert.equal(timeout, 360_000);
    assert.equal(limit, 16 * 1024 * 1024);
    assert.equal(existsSync(env.DOCKER_CONFIG), false);
  }
  assert.equal(hostedScannerImage, scannerImage);
  for (const args of [hostedScannerArguments(baseline.expectedImage, "json", "test", "/private-config"), scannerArguments("/test.sock", "test:local", "test")]) {
    assert.ok(args.includes("--ignore-unfixed=false"));
    assert.ok(args.includes("UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"));
    assert.equal(args[args.indexOf("--exit-code") + 1], "0");
  }
});

test("scanner failure removes only its named container, hides stderr, and writes no report", t => {
  const f = fixture(t);
  rmSync(join(f.evidence, "recommendation-mcp.cdx.json"));
  const calls = [];
  assert.throws(() => scanHosted(f.env, (args) => {
    calls.push(args);
    if (args.includes("run")) throw new Error("PRIVATE_SENTINEL");
    return Buffer.alloc(0);
  }), error => /Hosted Trivy scan failed/.test(error.message) && !error.message.includes("PRIVATE_SENTINEL"));
  assert.equal(calls[1].at(-1), calls[0][calls[0].indexOf("--name") + 1]);
  assert.equal(existsSync(join(f.evidence, "recommendation-mcp.cdx.json")), false);
});

test("metadata preserves default version and exact canonical/rejected membership", () => {
  const action = readFileSync(new URL("../actions/container-evidence/action.yml", import.meta.url), "utf8");
  assert.match(action, /default: v1alpha2/);
  assert.match(action, /EVIDENCE_VERSION: \$\{\{ steps.context.outputs.version \}\}/);
  const canonical = action.slice(action.indexOf("- name: Attest the exact four-file"), action.indexOf("- name: Upload rejected"));
  assert.equal((canonical.match(/steps.context.outputs.document/g) ?? []).length, 2);
  assert.ok(!canonical.includes("vulnerability-policy-diagnostic"));
  assert.ok(!canonical.includes("security-evidence/*"));
  const rejected = action.slice(action.indexOf("- name: Upload rejected"));
  assert.ok(rejected.includes("vulnerability-policy-diagnostic.json"));
  assert.ok(!rejected.includes("outputs.document"));
});
