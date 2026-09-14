/** Compose a fresh policy snapshot with the shared pure evaluator; never accept policy paths. */
import { acquirePolicy, githubPolicyReader, policyRepository } from "./policy-source.mjs";
import { evaluateVulnerabilities } from "./vulnerability-policy.mjs";
import { parseJson, sha256, requireRuntime } from "./runtime-files.mjs";
export async function evaluateApprovedReport(report, image, component, subjectKind, token, read = githubPolicyReader(token), now = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z")) {
    const parsed = parseJson(report);
    const snapshot = await acquirePolicy(component, read);
    return {
        source: { repository: policyRepository, revision: snapshot.revision },
        reportSha256: sha256(report),
        evaluation: evaluateVulnerabilities({ report: parsed, expectedImage: image, subjectKind,
            component, records: snapshot.records, useApprovedExemptions: true, now: now() }),
    };
}
/** Escape report/approval text before including it in GitHub Markdown or annotations. */
function escape(value) {
    return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
        .replaceAll("|", "&#124;").replaceAll("\r", "&#13;").replaceAll("\n", "&#10;");
}
/** Bounded presentation only; the retained JSON always has every finding and warning. */
export function renderApprovedSummary(decision, diagnostics) {
    const e = decision.evaluation;
    const lines = [
        "### Container vulnerability decision", "",
        `- Result: **${e.result}**`,
        `- Raw CRITICAL: **${e.counts.critical}**; blocking: **${e.blockingCritical}**`,
        `- Exempted: not affected **${e.exempted.notAffected}**, accepted risk **${e.exempted.riskAccepted}**`,
        `- HIGH: **${e.counts.high}** (non-blocking here; admission retains its operator-approval requirement)`,
        `- Policy revision: ${decision.source.revision}; decision time: ${e.evaluatedAt}`,
        `- Complete report and decision: ${escape(diagnostics)}`, "",
    ];
    let length = Buffer.byteLength(lines.join("\n"));
    const appendDetail = (line) => {
        const size = Buffer.byteLength(line) + 1;
        if (length + size > 192 * 1024)
            return false;
        lines.push(line);
        length += size;
        return true;
    };
    let omittedApprovals = 0;
    for (const { record } of e.exemptions) {
        if (!appendDetail(`- ${escape(record.id)} (${record.type}): ${escape(record.vex.statements[0].vulnerability.name)}, <code>${escape(record.package.name)} ${escape(record.package.version)}</code>; owner <code>${escape(record.owner)}</code>; expires ${record.expiresAt}.`))
            omittedApprovals++;
    }
    let omittedWarnings = 0;
    for (const warning of e.warnings) {
        if (!appendDetail(`- ${warning.code}: ${escape(warning.exemptionId)}`))
            omittedWarnings++;
    }
    if (omittedApprovals || omittedWarnings)
        lines.push(`${omittedApprovals} approval descriptions and ${omittedWarnings} warnings omitted from this summary; all remain in the complete retained JSON.`);
    lines.push("", "| CRITICAL | Package | Disposition | Approval |", "| --- | --- | --- | --- |");
    let shown = 0;
    for (const finding of e.findings) {
        if (finding.severity !== "CRITICAL")
            continue;
        const line = `| <code>${escape(finding.vulnerabilityId)}</code> | <code>${escape(finding.package.name)} ${escape(finding.package.version)}</code> | ${finding.disposition} | ${escape(finding.exemptionId ?? "none")} |`;
        if (!appendDetail(line))
            break;
        shown++;
    }
    if (shown < e.counts.critical)
        lines.push(`Summary shows ${shown} of ${e.counts.critical} CRITICAL findings; all findings and decisions remain in the retained JSON.`);
    lines.push("", "Local/PR and rejected diagnostics do not authorize publication or admission.", "");
    const summary = lines.join("\n");
    requireRuntime(Buffer.byteLength(summary) <= 256 * 1024, "Policy summary exceeds limit=262144 bytes; use the retained complete local diagnostics.");
    return summary;
}
