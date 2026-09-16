import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import Ajv from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { profileFor, publicationContext } from "../actions/container-evidence/lib/profile.mjs";
import { generateV3Evidence } from "../actions/container-evidence/lib/candidate-v3.mjs";
import { parseExemption } from "../actions/container-evidence/lib/exemption-policy.mjs";
import { baseline, policyFixture } from "./support/policy-fixture.mjs";

const component = "reservation-service";
const profile = profileFor(component);
const digest = `sha256:${"a".repeat(64)}`;
const image = `${profile.image}@${digest}`;
const schemaRoot = "https://schemas.movie-platform.dev/ci/";
const ajv = new Ajv({ strict: false, allErrors: true });
addFormats(ajv);
for (const name of ["component-candidate-evidence-v1alpha2", "container-vulnerability-exemption-v1alpha1", "component-candidate-evidence-v1alpha3"]) {
  ajv.addSchema(JSON.parse(readFileSync(new URL(`../contracts/${name}.schema.json`, import.meta.url))));
}
const validate = ajv.getSchema(`${schemaRoot}component-candidate-evidence-v1alpha3.schema.json`);
const validateRecord = ajv.getSchema(`${schemaRoot}container-vulnerability-exemption-v1alpha1.schema.json`);

function fixture(t, critical = false) {
  const directory = mkdtempSync(join(tmpdir(), "service-enrollment-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const evidence = join(directory, "security-evidence");
  mkdirSync(evidence);
  const report = structuredClone(baseline.report);
  report.ArtifactName = image;
  if (!critical) report.Results[0].Vulnerabilities = report.Results[0].Vulnerabilities.filter(v => v.Severity !== "CRITICAL");
  for (const [name, value] of [
    [profile.provenance, { mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json" }],
    [profile.sbom, { bomFormat: "CycloneDX", specVersion: "1.6", version: 1 }],
    [profile.vulnerabilities, report],
  ]) writeFileSync(join(evidence, name), JSON.stringify(value));
  const env = {
    COMPONENT: component, GITHUB_REPOSITORY: profile.repository,
    GITHUB_REF: "refs/heads/main", GITHUB_EVENT_NAME: "push", GITHUB_SERVER_URL: "https://github.com",
    GITHUB_JOB: "publish-candidate", GITHUB_SHA: "b".repeat(40), GITHUB_RUN_ID: "123", GITHUB_RUN_ATTEMPT: "2",
    CANDIDATE_DIGEST: digest, CANDIDATE_REPOSITORY: profile.image,
    GITHUB_WORKSPACE: directory, GITHUB_STEP_SUMMARY: join(directory, "summary"), GITHUB_OUTPUT: join(directory, "output"),
    ATTESTATION_ID: "456", ATTESTATION_URL: `https://github.com/${profile.repository}/attestations/456`, GH_TOKEN: "TOKEN_SENTINEL",
  };
  return { evidence, env, candidatePath: join(evidence, "component-candidate-evidence-v1alpha3.json") };
}

test("service enrollment preserves exact publication identity and refuses sibling contexts", t => {
  const { env } = fixture(t);
  assert.equal(profile.jobId, "publish-candidate");
  assert.equal(profile.jobName, "publish-candidate");
  assert.equal(profile.repository, "movie-reservation-platform-lab/movie-reservation-service");
  assert.equal(profile.image, "ghcr.io/movie-reservation-platform-lab/movie-reservation-service");
  const context = publicationContext(env);
  assert.equal(context.artifact, "reservation-service-security-evidence-123-attempt-2");
  assert.equal(context.tag, `sha-${env.GITHUB_SHA}-run-123-attempt-2`);
  for (const [key, value] of Object.entries({
    GITHUB_JOB: "publish-image", GITHUB_EVENT_NAME: "pull_request", GITHUB_REF: "refs/heads/topic",
    GITHUB_REPOSITORY: "movie-reservation-platform-lab/movie-recommendation-mcp", GITHUB_RUN_ATTEMPT: "0",
  })) assert.throws(() => publicationContext({ ...env, [key]: value }));
});

test("service v3 writer emits exact schema bindings without changing report bytes", async t => {
  const f = fixture(t);
  const bytes = readFileSync(join(f.evidence, profile.vulnerabilities));
  const policy = policyFixture([], component);
  await generateV3Evidence(f.env, policy.read, () => baseline.now);
  const candidate = JSON.parse(readFileSync(f.candidatePath));
  assert.equal(validate(candidate), true, JSON.stringify(validate.errors));
  assert.equal(candidate.workflow.job, "publish-candidate");
  assert.equal(candidate.workflow.runId, "123");
  assert.equal(candidate.workflow.runAttempt, 2);
  assert.equal(candidate.provenance.subjectDigest, digest);
  assert.equal(candidate.securityEvidence.vulnerabilities.subject, image);
  assert.deepEqual(readFileSync(join(f.evidence, profile.vulnerabilities)), bytes);
  assert.equal(policy.calls.filter(c => c.endpoint.endsWith("ref/heads/main")).length, 1);
  for (const [section, field, value] of [
    ["source", "repository", "attacker/movie-reservation-service"],
    ["workflow", "job", "publish immutable GHCR image"],
    ["candidate", "repository", "ghcr.io/attacker/movie-reservation-service"],
    ["provenance", "subjectName", "ghcr.io/attacker/movie-reservation-service"],
  ]) {
    const changed = structuredClone(candidate);
    changed[section][field] = value;
    assert.equal(validate(changed), false, `${section}.${field} must remain bound`);
  }
  for (const section of ["sbom", "vulnerabilities"]) {
    const changed = structuredClone(candidate);
    changed.securityEvidence[section].path = "security-evidence/other.json";
    assert.equal(validate(changed), false);
  }
  const legacy = structuredClone(candidate);
  legacy.apiVersion = "ci.movie-platform.dev/v1alpha2";
  delete legacy.securityEvidence.vulnerabilityPolicy;
  assert.equal(ajv.getSchema(`${schemaRoot}component-candidate-evidence-v1alpha2.schema.json`)(legacy), false);
});

test("service requires explicit v3 before context output or direct legacy emission", t => {
  for (const version of [undefined, "v1alpha2"]) for (const script of ["context.mjs", "write-candidate-evidence.mjs"]) {
    const f = fixture(t);
    const env = { ...f.env };
    if (version) env.EVIDENCE_VERSION = version;
    const result = spawnSync(process.execPath, [fileURLToPath(new URL(`../actions/container-evidence/lib/${script}`, import.meta.url))], { env, encoding: "utf8", timeout: 5000 });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /requires explicit v1alpha3/);
    assert.equal(existsSync(f.env.GITHUB_OUTPUT), false);
    assert.equal(existsSync(join(f.evidence, "component-candidate-evidence-v1alpha2.json")), false);
  }
});

test("service CRITICAL findings require service-scoped reviewed coverage", async t => {
  const blocked = fixture(t, true);
  await assert.rejects(generateV3Evidence(blocked.env, policyFixture([], component).read, () => baseline.now), /Unapproved CRITICAL/);
  assert.equal(existsSync(blocked.candidatePath), false);

  const record = structuredClone(baseline.records[0]);
  record.component = component;
  record.vex.statements[0].products[0]["@id"] = `https://github.com/${profile.repository}`;
  assert.equal(validateRecord(record), true, JSON.stringify(validateRecord.errors));
  assert.deepEqual(parseExemption(record), record);
  const allowed = fixture(t, true);
  await generateV3Evidence(allowed.env, policyFixture([record], component).read, () => baseline.now);
  const candidate = JSON.parse(readFileSync(allowed.candidatePath));
  assert.equal(validate(candidate), true, JSON.stringify(validate.errors));
  assert.equal(candidate.securityEvidence.vulnerabilityPolicy.evaluation.result, "passed-with-exemptions");

  record.vex.statements[0].products[0]["@id"] = "https://github.com/movie-reservation-platform-lab/movie-recommendation-mcp";
  assert.equal(validateRecord(record), false);
  assert.throws(() => parseExemption(record));
  const wrongScope = fixture(t, true);
  await assert.rejects(generateV3Evidence(wrongScope.env, policyFixture(baseline.records, component).read, () => baseline.now));
  assert.equal(existsSync(wrongScope.candidatePath), false);
});

test("service policy acquisition failure never creates evidence or an empty approval set", async t => {
  const f = fixture(t);
  await assert.rejects(generateV3Evidence(f.env, async () => { throw new Error("unavailable"); }, () => baseline.now));
  assert.equal(existsSync(f.candidatePath), false);
});
