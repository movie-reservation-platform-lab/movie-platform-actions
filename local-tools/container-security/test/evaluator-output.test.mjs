import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseEvaluatorOutput, validateApprovedDiagnostic, validateStrictResult } from "../lib/evaluator-output.mjs";

const candidate = JSON.parse(readFileSync(new URL("../../../test/fixtures/vulnerability-policy/candidate-v1alpha3.json", import.meta.url)));
const expectedImage = candidate.securityEvidence.vulnerabilityPolicy.evaluation.subject;
const approvedOutput = "high-count=1\ncritical-count=1\npolicy-result=passed-with-exemptions\n";

function approvedDiagnostic() {
  return { diagnosticOnly: true, evaluation: structuredClone(candidate.securityEvidence.vulnerabilityPolicy.evaluation) };
}

test("approved raw CRITICALs can pass v3 while the same result is invalid for legacy strict mode", () => {
  const output = parseEvaluatorOutput(approvedOutput);
  assert.deepEqual(output, { highCount: "1", criticalCount: "1", policyResult: "passed-with-exemptions", expectedExitCode: 0 });
  assert.doesNotThrow(() => validateApprovedDiagnostic(approvedDiagnostic(), expectedImage, output));
  assert.throws(() => validateStrictResult(output), /inconsistent strict policy result/);
  assert.doesNotThrow(() => validateStrictResult(parseEvaluatorOutput("high-count=1\ncritical-count=0\npolicy-result=passed\n")));
  assert.doesNotThrow(() => validateStrictResult(parseEvaluatorOutput("high-count=1\ncritical-count=1\npolicy-result=failed\n")));
});

test("incomplete, unknown or extra subprocess output cannot select a policy pass", () => {
  for (const output of ["", approvedOutput + "extra=1\n", approvedOutput.replace("passed-with-exemptions", "approved"), approvedOutput.replace("critical-count=1", "critical-count=-1")]) {
    assert.equal(parseEvaluatorOutput(output), undefined);
  }
});

for (const scenario of [
  { name: "missing diagnostic marker", change: diagnostic => { diagnostic.diagnosticOnly = false; }, expected: /missing diagnostic-only marker/ },
  { name: "missing count object", change: diagnostic => { delete diagnostic.evaluation.counts; }, expected: /missing approved evaluation\/count objects/ },
  { name: "different image", change: diagnostic => { diagnostic.evaluation.subject = "different:local"; }, expected: /describes a different image/ },
  { name: "different policy result", change: diagnostic => { diagnostic.evaluation.result = "failed"; }, expected: /policy results disagree/ },
  { name: "different raw count", change: diagnostic => { diagnostic.evaluation.counts.critical++; }, expected: /raw finding counts disagree/ },
  { name: "negative exemption count", change: diagnostic => { diagnostic.evaluation.exempted.notAffected = -1; }, expected: /nonnegative safe integers/ },
  { name: "missing coverage", change: diagnostic => { diagnostic.evaluation.exempted.notAffected = 0; }, expected: /do not account for every raw CRITICAL/ },
  { name: "blocking result claims successful exit", change: diagnostic => { diagnostic.evaluation.exempted.notAffected = 0; diagnostic.evaluation.blockingCritical = 1; }, expected: /disagrees with the policy exit code/ },
]) {
  test(`local v3 output refuses ${scenario.name} for its specific inconsistency`, () => {
    const diagnostic = approvedDiagnostic();
    scenario.change(diagnostic);
    assert.throws(() => validateApprovedDiagnostic(diagnostic, expectedImage, parseEvaluatorOutput(approvedOutput)), scenario.expected);
  });
}

test("a covered CRITICAL must be reported as passed-with-exemptions, not an ordinary pass", () => {
  const diagnostic = approvedDiagnostic();
  diagnostic.evaluation.result = "passed";
  const output = parseEvaluatorOutput(approvedOutput.replace("passed-with-exemptions", "passed"));
  assert.throws(() => validateApprovedDiagnostic(diagnostic, expectedImage, output), /must be identified as passed-with-exemptions/);
});
