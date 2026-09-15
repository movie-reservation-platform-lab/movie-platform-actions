/**
 * Checks that the vulnerability report (trivy) belongs to the expected container image,
 * then writes finding counts and a summary to GitHub Actions. Fails the step for
 * invalid reports or CRITICAL findings; HIGH findings are reported but do not fail it.
 */
import { appendFileSync } from "node:fs";
import { readDocument, RuntimeError } from "./runtime-files.mjs";
const immutableGhcrImagePattern = /^ghcr\.io\/[a-z0-9_.-]+\/[a-z0-9_.-]+@sha256:[0-9a-f]{64}$/;
const localImagePattern = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;
const artifactNamePattern = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,127})$/;
const supportedSeverities = new Set([
    "UNKNOWN",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
]);
if (process.env.EVIDENCE_VERSION === "v1alpha3") {
    const { runLocalEvaluation } = await import("./evaluate-v3.mjs");
    await runLocalEvaluation(process.env);
}
else if (process.env.EVIDENCE_VERSION && process.env.EVIDENCE_VERSION !== "v1alpha2") {
    reportWorkflowError("Unsupported evidence version.");
    process.exitCode = 2;
}
else
    try {
        const reportPathInput = requireEnvironmentVariable("REPORT_PATH");
        const expectedImage = requireEnvironmentVariable("EXPECTED_IMAGE");
        const subjectKind = parseSubjectKind(requireEnvironmentVariable("SUBJECT_KIND"));
        const evidenceArtifactName = requireEnvironmentVariable("EVIDENCE_ARTIFACT_NAME");
        const githubOutput = requireEnvironmentVariable("GITHUB_OUTPUT");
        const githubStepSummary = requireEnvironmentVariable("GITHUB_STEP_SUMMARY");
        const githubWorkspace = requireEnvironmentVariable("GITHUB_WORKSPACE");
        validateExpectedImage(expectedImage, subjectKind);
        if (!artifactNamePattern.test(evidenceArtifactName)) {
            throw new RuntimeError("Evidence artifact name contains unsupported characters.");
        }
        const report = readTrivyReport(githubWorkspace, reportPathInput);
        if (report.ArtifactName !== expectedImage) {
            throw new RuntimeError("Trivy report artifact does not match expected image.");
        }
        const vulnerabilities = collectVulnerabilities(report.Results);
        const highCount = vulnerabilities.filter((vulnerability) => vulnerability.severity === "HIGH").length;
        const criticalFindings = vulnerabilities.filter((vulnerability) => vulnerability.severity === "CRITICAL");
        const criticalCount = criticalFindings.length;
        const policyResult = criticalCount === 0 ? "passed" : "failed";
        appendFileSync(githubOutput, [
            `high-count=${highCount}`,
            `critical-count=${criticalCount}`,
            `policy-result=${policyResult}`,
            "",
        ].join("\n"));
        appendFileSync(githubStepSummary, renderSummary({
            criticalCount,
            criticalFindings,
            evidenceArtifactName,
            expectedImage,
            highCount,
            policyResult,
            subjectKind,
        }));
        if (criticalCount > 0) {
            reportWorkflowError(`Provisional container policy failed: ${criticalCount} CRITICAL vulnerability finding(s) detected.`);
            process.exitCode = 1;
        }
    }
    catch (error) {
        const message = error instanceof RuntimeError ? error.message : "Report or workflow file operation failed.";
        reportWorkflowError(`Unable to evaluate container vulnerability evidence: ${message}`);
        process.exitCode = 1;
    }
/** Accepts only the supported image kinds: an immutable GHCR image or a local image. */
function parseSubjectKind(value) {
    if (value === "immutable-ghcr" || value === "local") {
        return value;
    }
    throw new RuntimeError("Unsupported image subject kind.");
}
/** Requires a GHCR digest reference or a local image tag, depending on the image kind. */
function validateExpectedImage(expectedImage, subjectKind) {
    if (subjectKind === "immutable-ghcr" &&
        !immutableGhcrImagePattern.test(expectedImage)) {
        throw new RuntimeError("Expected image is not an immutable GHCR reference.");
    }
    if (subjectKind === "local" && !localImagePattern.test(expectedImage)) {
        throw new RuntimeError("Expected image is not a supported local container reference.");
    }
}
/** Reads a required runner setting, rejecting missing or empty values. */
function requireEnvironmentVariable(name) {
    const value = process.env[name];
    if (value === undefined || value.length === 0) {
        throw new RuntimeError(`Required environment variable ${name} is missing.`);
    }
    return value;
}
/** Reads a Trivy v2 container report; its vulnerability results are validated separately. */
function readTrivyReport(workspace, path) {
    const bytes = readDocument(workspace, path, 64 * 1024 * 1024, "Vulnerability report");
    let parsed;
    try {
        parsed = JSON.parse(bytes.toString("utf8"));
    }
    catch {
        throw new RuntimeError("Trivy report must be valid JSON.");
    }
    if (!isRecord(parsed)) {
        throw new RuntimeError("Trivy report root must be a JSON object.");
    }
    if (parsed.SchemaVersion !== 2) {
        throw new RuntimeError("Unsupported Trivy report schema version.");
    }
    if (parsed.ArtifactType !== "container_image") {
        throw new RuntimeError("Trivy report artifact type must be container_image.");
    }
    if (typeof parsed.ArtifactName !== "string") {
        throw new RuntimeError("Trivy report ArtifactName must be a string.");
    }
    return { ArtifactName: parsed.ArtifactName, Results: parsed.Results };
}
/** Combines findings across scan results; missing or null results count as no findings. */
function collectVulnerabilities(resultsValue) {
    if (resultsValue === undefined || resultsValue === null) {
        return [];
    }
    if (!Array.isArray(resultsValue)) {
        throw new RuntimeError("Trivy report Results must be an array when present.");
    }
    return resultsValue.flatMap((result, resultIndex) => collectResultVulnerabilities(result, resultIndex));
}
/** Validates one scan result and reads its findings, allowing a missing or null list. */
function collectResultVulnerabilities(resultValue, resultIndex) {
    if (!isRecord(resultValue)) {
        throw new RuntimeError(`Trivy result at index ${resultIndex} must be an object.`);
    }
    const vulnerabilities = resultValue.Vulnerabilities;
    if (vulnerabilities === undefined || vulnerabilities === null) {
        return [];
    }
    if (!Array.isArray(vulnerabilities)) {
        throw new RuntimeError(`Trivy vulnerabilities at result index ${resultIndex} must be an array.`);
    }
    return vulnerabilities.map((vulnerability, vulnerabilityIndex) => parseVulnerability(vulnerability, resultIndex, vulnerabilityIndex));
}
/**
 * Validates one finding and normalizes its severity to uppercase.
 * A missing or blank fixed version means the report lists no fix.
 */
function parseVulnerability(vulnerabilityValue, resultIndex, vulnerabilityIndex) {
    if (!isRecord(vulnerabilityValue)) {
        throw new RuntimeError(`Trivy vulnerability at result ${resultIndex}, index ${vulnerabilityIndex} must be an object.`);
    }
    const vulnerabilityId = requireReportString(vulnerabilityValue, "VulnerabilityID", resultIndex, vulnerabilityIndex);
    const packageName = requireReportString(vulnerabilityValue, "PkgName", resultIndex, vulnerabilityIndex);
    const installedVersion = requireReportString(vulnerabilityValue, "InstalledVersion", resultIndex, vulnerabilityIndex);
    const severity = requireReportString(vulnerabilityValue, "Severity", resultIndex, vulnerabilityIndex).toUpperCase();
    const fixedVersionValue = vulnerabilityValue.FixedVersion;
    if (!supportedSeverities.has(severity)) {
        throw new RuntimeError(`Trivy vulnerability at result ${resultIndex}, index ${vulnerabilityIndex} has unsupported severity.`);
    }
    if (fixedVersionValue !== undefined &&
        typeof fixedVersionValue !== "string") {
        throw new RuntimeError(`Trivy vulnerability at result ${resultIndex}, index ${vulnerabilityIndex} has no valid FixedVersion.`);
    }
    return {
        fixedVersion: typeof fixedVersionValue === "string" &&
            fixedVersionValue.trim().length > 0
            ? fixedVersionValue
            : undefined,
        installedVersion,
        packageName,
        severity: severity,
        vulnerabilityId,
    };
}
/** Reads a nonempty text field, identifying the finding's position if it is invalid. */
function requireReportString(vulnerability, field, resultIndex, vulnerabilityIndex) {
    const value = vulnerability[field];
    if (typeof value !== "string" || value.length === 0) {
        throw new RuntimeError(`Trivy vulnerability at result ${resultIndex}, index ${vulnerabilityIndex} has no valid ${field}.`);
    }
    return value;
}
/** Builds the job summary with finding counts, CRITICAL details, and the HIGH approval reminder. */
function renderSummary({ criticalCount, criticalFindings, evidenceArtifactName, expectedImage, highCount, policyResult, subjectKind, }) {
    const highDecision = highCount === 0
        ? "No HIGH findings require an admission decision for this candidate."
        : "HIGH findings do not fail this provisional gate, but admission requires explicit, recorded operator approval.";
    const subjectLabel = subjectKind === "immutable-ghcr" ? "Immutable candidate" : "Local PR image";
    const summary = [
        "### Provisional container security evidence",
        "",
        `- ${subjectLabel}: \`${expectedImage}\``,
        "- Scanner: `Trivy`",
        `- HIGH findings: **${highCount}**`,
        `- CRITICAL findings: **${criticalCount}**`,
        `- Provisional policy: **${policyResult.toUpperCase()}**`,
        `- Downloadable evidence artifact: \`${evidenceArtifactName}\``,
        "",
    ];
    if (criticalFindings.length > 0) {
        summary.push("#### CRITICAL findings", "", "| Vulnerability | Package | Installed version | Fixed version |", "| --- | --- | --- | --- |", ...criticalFindings.map(renderCriticalFinding), "");
    }
    summary.push(highDecision, "", "This CRITICAL-only control is provisional pending the durable [platform policy in `.github#8`](https://github.com/movie-reservation-platform-lab/.github/issues/8).", "");
    return summary.join("\n");
}
/** Formats one CRITICAL finding as a table row, explicitly noting when no fix is reported. */
function renderCriticalFinding(vulnerability) {
    const fixedVersion = vulnerability.fixedVersion === undefined
        ? "<em>no fix reported</em>"
        : `<code>${escapeSummaryValue(vulnerability.fixedVersion)}</code>`;
    return `| <code>${escapeSummaryValue(vulnerability.vulnerabilityId)}</code> | <code>${escapeSummaryValue(vulnerability.packageName)}</code> | <code>${escapeSummaryValue(vulnerability.installedVersion)}</code> | ${fixedVersion} |`;
}
/** Escapes report text so it cannot introduce HTML or break the summary's table cells. */
function escapeSummaryValue(value) {
    return value
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll("|", "&#124;")
        .replaceAll("\r", "&#13;")
        .replaceAll("\n", "&#10;");
}
/** Emits a GitHub Actions error annotation, escaping workflow-command control characters. */
function reportWorkflowError(message) {
    const escapedMessage = message
        .replaceAll("%", "%25")
        .replaceAll("\r", "%0D")
        .replaceAll("\n", "%0A");
    console.error(`::error::${escapedMessage}`);
}
/** Narrows a JSON value to an object with readable fields, excluding null and arrays. */
function isRecord(value) {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}
