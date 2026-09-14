/** Compose a fresh policy snapshot with the shared pure evaluator; never accept policy paths. */
import { acquirePolicy, githubPolicyReader, policyRepository } from "./policy-source.mjs";
import { evaluateVulnerabilities } from "./vulnerability-policy.mjs";
import { parseJson, sha256, requireRuntime } from "./runtime-files.mjs";
/**
 * Authenticate the selected component's latest policy and evaluate original report bytes once.
 * The clock is sampled after acquisition so approvals are checked at the decision time.
 * Injected transport/time functions are for offline tests; callers cannot supply policy files.
 */
export async function evaluateApprovedReport(reportBytes, expectedImage, component, subjectKind, token, readPolicyJson = githubPolicyReader(token), decisionTime = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z")) {
    const report = parseJson(reportBytes);
    const snapshot = await acquirePolicy(component, readPolicyJson);
    return {
        source: { repository: policyRepository, revision: snapshot.revision },
        reportSha256: sha256(reportBytes),
        evaluation: evaluateVulnerabilities({ report, expectedImage, subjectKind,
            component, records: snapshot.records, useApprovedExemptions: true, now: decisionTime() }),
    };
}
/** Escape report/approval text before including it in GitHub Markdown or annotations. */
function escapeSummaryText(value) {
    return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
        .replaceAll("|", "&#124;").replaceAll("\r", "&#13;").replaceAll("\n", "&#10;");
}
/** Bounded presentation only; the retained JSON always has every finding and warning. */
export function renderApprovedSummary(decision, diagnosticLocation) {
    const evaluation = decision.evaluation;
    const lines = [
        "### Container vulnerability decision", "",
        `- Result: **${evaluation.result}**`,
        `- Raw CRITICAL: **${evaluation.counts.critical}**; blocking: **${evaluation.blockingCritical}**`,
        `- Exempted: not affected **${evaluation.exempted.notAffected}**, accepted risk **${evaluation.exempted.riskAccepted}**`,
        `- HIGH: **${evaluation.counts.high}** (non-blocking here; admission retains its operator-approval requirement)`,
        `- Policy revision: ${decision.source.revision}; decision time: ${evaluation.evaluatedAt}`,
        `- Complete report and decision: ${escapeSummaryText(diagnosticLocation)}`, "",
    ];
    let summaryBytes = Buffer.byteLength(lines.join("\n"));
    const appendDetail = (line) => {
        const lineBytes = Buffer.byteLength(line) + 1;
        if (summaryBytes + lineBytes > 192 * 1024)
            return false;
        lines.push(line);
        summaryBytes += lineBytes;
        return true;
    };
    let omittedApprovals = 0;
    for (const { record } of evaluation.exemptions) {
        if (!appendDetail(`- ${escapeSummaryText(record.id)} (${record.type}): ${escapeSummaryText(record.vex.statements[0].vulnerability.name)}, <code>${escapeSummaryText(record.package.name)} ${escapeSummaryText(record.package.version)}</code>; owner <code>${escapeSummaryText(record.owner)}</code>; expires ${record.expiresAt}.`))
            omittedApprovals++;
    }
    let omittedWarnings = 0;
    for (const warning of evaluation.warnings) {
        if (!appendDetail(`- ${warning.code}: ${escapeSummaryText(warning.exemptionId)}`))
            omittedWarnings++;
    }
    if (omittedApprovals || omittedWarnings)
        lines.push(`${omittedApprovals} approval descriptions and ${omittedWarnings} warnings omitted from this summary; all remain in the complete retained JSON.`);
    lines.push("", "| CRITICAL | Package | Disposition | Approval |", "| --- | --- | --- | --- |");
    let shownCriticalFindings = 0;
    for (const finding of evaluation.findings) {
        if (finding.severity !== "CRITICAL")
            continue;
        const line = `| <code>${escapeSummaryText(finding.vulnerabilityId)}</code> | <code>${escapeSummaryText(finding.package.name)} ${escapeSummaryText(finding.package.version)}</code> | ${finding.disposition} | ${escapeSummaryText(finding.exemptionId ?? "none")} |`;
        if (!appendDetail(line))
            break;
        shownCriticalFindings++;
    }
    if (shownCriticalFindings < evaluation.counts.critical)
        lines.push(`Summary shows ${shownCriticalFindings} of ${evaluation.counts.critical} CRITICAL findings; all findings and decisions remain in the retained JSON.`);
    lines.push("", "Local/PR and rejected diagnostics do not authorize publication or admission.", "");
    const summary = lines.join("\n");
    requireRuntime(Buffer.byteLength(summary) <= 256 * 1024, "Policy summary exceeds limit=262144 bytes; use the retained complete local diagnostics.");
    return summary;
}
