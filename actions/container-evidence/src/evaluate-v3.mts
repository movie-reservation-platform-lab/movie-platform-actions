/** Diagnostic-only local/PR v3 entrypoint; acquisition is independent of producer files. */
import { appendFileSync, realpathSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { evaluateApprovedReport, renderApprovedSummary } from "./approved-evaluation.mjs";
import { readDocument, requireRuntime, safeFailure, writeJson } from "./runtime-files.mjs";

export async function runLocalEvaluation(env: NodeJS.ProcessEnv): Promise<void> {
  try {
    requireRuntime(env.SUBJECT_KIND === "local", "This v3 evaluator only produces non-admissible local/PR diagnostics.");
    requireRuntime(env.COMPONENT && env.EXPECTED_IMAGE && env.GITHUB_WORKSPACE && env.REPORT_PATH && env.GITHUB_OUTPUT && env.GITHUB_STEP_SUMMARY, "Local v3 evaluation requires component, image, report and output context.");
    const workspace = realpathSync(env.GITHUB_WORKSPACE);
    const bytes = readDocument(workspace, env.REPORT_PATH, 64 * 1024 * 1024, "Local vulnerability report");
    const decision = await evaluateApprovedReport(bytes, env.EXPECTED_IMAGE, env.COMPONENT, "local", env.GH_TOKEN);
    writeJson(join(workspace, "vulnerability-policy.json"), { diagnosticOnly: true, ...decision }, 1024 * 1024, "Local policy diagnostic");
    appendFileSync(env.GITHUB_STEP_SUMMARY, renderApprovedSummary(decision, "vulnerabilities.json and vulnerability-policy.json"));
    const e = decision.evaluation;
    appendFileSync(env.GITHUB_OUTPUT, `high-count=${e.counts.high}\ncritical-count=${e.counts.critical}\npolicy-result=${e.result}\n`);
    process.exitCode = e.blockingCritical === 0 ? 0 : 1;
  } catch (error) {
    const message = safeFailure(error);
    if (env.GITHUB_WORKSPACE) {
      try { writeFileSync(join(realpathSync(env.GITHUB_WORKSPACE), "vulnerability-policy-error.txt"), message + "\n", { flag: "wx", mode: 0o600 }); }
      catch { /* The controlled stderr message still reports the operational failure. */ }
    }
    console.error(message);
    process.exitCode = 2;
  }
}
