/** Validate the local evaluator's output protocol without treating diagnostics as publication authority. */

type PolicyResult = "passed" | "passed-with-exemptions" | "failed";
export type EvaluatorOutput = {
  highCount: string;
  criticalCount: string;
  policyResult: PolicyResult;
  expectedExitCode: 0 | 1;
};

/** Give the three output lines names; malformed or extra lines are an operational failure. */
export function parseEvaluatorOutput(outputText: string): EvaluatorOutput | undefined {
  const fields = /^high-count=(\d+)\ncritical-count=(\d+)\npolicy-result=(passed|passed-with-exemptions|failed)\n$/.exec(outputText);
  if (!fields) return undefined;
  return {
    highCount: fields[1]!,
    criticalCount: fields[2]!,
    policyResult: fields[3] as PolicyResult,
    expectedExitCode: fields[3] === "failed" ? 1 : 0,
  };
}

/** Legacy success always means zero raw CRITICALs; it can never report an exemption-assisted pass. */
export function validateStrictResult(output: EvaluatorOutput): void {
  if (output.policyResult === "passed-with-exemptions" ||
      (output.criticalCount === "0") !== (output.expectedExitCode === 0)) {
    throw new Error("Report/evaluator failure: inconsistent strict policy result.");
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isFindingCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

/** Use controlled diagnostics that describe the broken output relationship, never raw child stderr. */
function requireDiagnostic(condition: unknown, explanation: string): asserts condition {
  if (!condition) throw new Error(`Report/evaluator failure: ${explanation}.`);
}

/**
 * Check that retained v3 diagnostics explain the subprocess's subject, counts and result.
 * Raw CRITICALs may remain on a pass: blocking + both approved categories must equal
 * the raw count, and only the blocking count determines the successful exit code.
 */
export function validateApprovedDiagnostic(diagnostic: unknown, expectedImage: string, output: EvaluatorOutput): void {
  requireDiagnostic(isObject(diagnostic) && diagnostic.diagnosticOnly === true, "missing diagnostic-only marker");
  const evaluation = diagnostic.evaluation;
  requireDiagnostic(isObject(evaluation) && isObject(evaluation.counts) && isObject(evaluation.exempted), "missing approved evaluation/count objects");

  requireDiagnostic(evaluation.subject === expectedImage, "approved diagnostic describes a different image");
  requireDiagnostic(evaluation.result === output.policyResult, "diagnostic and subprocess policy results disagree");
  requireDiagnostic(
    evaluation.counts.high === Number(output.highCount) && evaluation.counts.critical === Number(output.criticalCount),
    "diagnostic and subprocess raw finding counts disagree",
  );

  const blockingCritical = evaluation.blockingCritical;
  const notAffectedCritical = evaluation.exempted.notAffected;
  const riskAcceptedCritical = evaluation.exempted.riskAccepted;
  requireDiagnostic(
    isFindingCount(blockingCritical) && isFindingCount(notAffectedCritical) && isFindingCount(riskAcceptedCritical),
    "blocking and exempted finding counts must be nonnegative safe integers",
  );
  requireDiagnostic(
    blockingCritical + notAffectedCritical + riskAcceptedCritical === evaluation.counts.critical,
    "blocking and exempted counts do not account for every raw CRITICAL",
  );
  requireDiagnostic(
    (blockingCritical === 0) === (output.expectedExitCode === 0),
    "blocking CRITICAL count disagrees with the policy exit code",
  );
  requireDiagnostic(
    (evaluation.result === "passed") === (evaluation.counts.critical === 0),
    "a pass with raw CRITICAL findings must be identified as passed-with-exemptions",
  );
}
