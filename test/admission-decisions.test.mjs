/** Shared decision examples; this is not an authenticated admission adapter. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import Ajv from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { evaluateVulnerabilities } from "../actions/container-evidence/lib/vulnerability-policy.mjs";
import { exemptionDigest } from "../actions/container-evidence/lib/exemption-policy.mjs";

const json = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8"));
const baseline = json("./fixtures/vulnerability-policy/baseline.json");
const records = {
  baseline: baseline.records[0],
  "risk-accepted": json("./fixtures/vulnerability-policy/risk-accepted.json"),
  renewed: json("./fixtures/vulnerability-policy/renewed.json"),
};
const fixtures = json("./fixtures/vulnerability-policy/admission-cases.json");
const ajv = new Ajv({ strict: false, allErrors: true });
addFormats(ajv);
for (const name of ["component-candidate-evidence-v1alpha2", "container-vulnerability-exemption-v1alpha1", "component-candidate-evidence-v1alpha3"]) {
  ajv.addSchema(json(`../contracts/${name}.schema.json`));
}
const validateEvaluation = ajv.compile({
  $ref: "https://schemas.movie-platform.dev/ci/component-candidate-evidence-v1alpha3.schema.json#/$defs/evaluation",
});

function assertDecision(actual, expected) {
  assert.equal(validateEvaluation(actual), true, JSON.stringify(validateEvaluation.errors));
  assert.deepEqual({
    result: actual.result,
    blockingCritical: actual.blockingCritical,
    notAffected: actual.exempted.notAffected,
    riskAccepted: actual.exempted.riskAccepted,
    usedIds: actual.exemptions.map(({ record }) => record.id),
    dispositions: actual.findings.map(({ disposition }) => disposition),
    warnings: actual.warnings.map(({ code }) => code),
  }, expected);
  assert.deepEqual(actual.counts, { unknown: 0, low: 0, medium: 0, high: 1, critical: 1 });
}

for (const scenario of fixtures.cases) {
  test(`historical/current decision vector: ${scenario.name}`, () => {
    const historicalInput = structuredClone(baseline);
    const historical = evaluateVulnerabilities(historicalInput);
    assertDecision(historical, fixtures.historicalExpected);
    const savedHistorical = structuredClone(historical);

    const currentInput = structuredClone(baseline);
    currentInput.now = scenario.now;
    currentInput.records = scenario.records.map((name) => {
      assert.ok(Object.hasOwn(records, name), `unknown fixture record: ${name}`);
      return structuredClone(records[name]);
    });
    // Same tiny JSON-pointer set/delete format as the existing shared vectors.
    for (const change of scenario.changes) {
      const path = change.path.slice(1).split("/").map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"));
      const key = path.pop();
      const parent = path.reduce((value, part) => value[part], currentInput);
      if (change.remove) delete parent[key];
      else parent[key] = structuredClone(change.value);
    }
    const savedCurrentInput = structuredClone(currentInput);
    if (scenario.error) {
      assert.throws(() => evaluateVulnerabilities(currentInput), { code: scenario.error });
    } else {
      const current = evaluateVulnerabilities(currentInput);
      assertDecision(current, scenario.expected);
      assert.equal(current.evaluatedAt, scenario.now);
      assert.equal(current.subject, historical.subject);
      // Retain the actual current approval, including rationale and expiry.
      for (const used of current.exemptions) {
        assert.deepEqual(used.record, currentInput.records.find(({ id }) => id === used.record.id));
        assert.equal(used.sha256, exemptionDigest(used.record));
      }
      assert.deepEqual(current.findings.map(({ disposition, exemptionId, ...finding }) => finding),
        historical.findings.map(({ disposition, exemptionId, ...finding }) => finding));
    }
    assert.deepEqual(currentInput.report, baseline.report, "current policy does not rescan or rewrite the original report");
    assert.deepEqual(currentInput, savedCurrentInput);
    assert.deepEqual(historicalInput, baseline);
    assert.deepEqual(historical, savedHistorical, "current policy must not rewrite producer evidence");
  });
}
