/**
 * Converts an untrusted Trivy schema-version-2 container report into finding facts
 * for policy evaluation. Checks report identity and size limits without modifying
 * the input or dropping findings whose package identifiers cannot earn exemptions.
 */
import { PolicyError, validateArray, validateObject, validatePackagePurl, assertPolicyCondition, validateText } from "./policy-values.mjs";
export const severities = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
export const maxFindings = 10_000;
/**
 * Validates the report and extracts findings in their original order.
 *
 * @param untrustedReport - Parsed Trivy JSON, not yet validated; not a JSON string or file path.
 * @param expectedImage - Exact image reference that the report's ArtifactName must match.
 * @param requirePlatform - Whether to require reported linux/amd64 platform metadata;
 * enabled when evaluating approved exemptions.
 * @returns Finding facts with pointers into the original report. Missing or null
 * result/vulnerability lists contribute no findings; ineligible PURLs become null.
 * @throws {PolicyError} If report identity, required fields, platform, or limits are invalid.
 */
export function readTrivyFindings(untrustedReport, expectedImage, requirePlatform) {
    const report = validateObject(untrustedReport);
    assertPolicyCondition(report.SchemaVersion === 2 && report.ArtifactType === "container_image", "unsupported-report");
    assertPolicyCondition(report.ArtifactName === expectedImage, "report-subject-mismatch");
    if (requirePlatform) {
        const config = validateObject(validateObject(report.Metadata).ImageConfig);
        assertPolicyCondition(config.os === "linux" && config.architecture === "amd64", "report-platform-mismatch");
    }
    const results = report.Results == null ? [] : validateArray(report.Results, 4096);
    const findings = [];
    for (const [resultIndex, untrustedResult] of results.entries()) {
        const result = validateObject(untrustedResult);
        const vulnerabilities = result.Vulnerabilities == null ? [] : validateArray(result.Vulnerabilities, maxFindings);
        assertPolicyCondition(findings.length + vulnerabilities.length <= maxFindings, "too-many-findings");
        for (const [findingIndex, untrustedFinding] of vulnerabilities.entries()) {
            const finding = validateObject(untrustedFinding);
            const name = validateText(finding.PkgName, 256);
            const version = validateText(finding.InstalledVersion, 256);
            const severity = validateText(finding.Severity, 16).toUpperCase();
            assertPolicyCondition(severities.includes(severity), "unsupported-severity");
            assertPolicyCondition(finding.FixedVersion === undefined || typeof finding.FixedVersion === "string", "invalid-fixed-version");
            findings.push({
                pointer: `/Results/${resultIndex}/Vulnerabilities/${findingIndex}`,
                vulnerabilityId: validateText(finding.VulnerabilityID, 64),
                package: { name, version, purl: eligiblePurl(finding.PkgIdentifier, version) },
                severity: severity,
            });
        }
    }
    return findings;
}
/**
 * Reads a package URL eligible for exact exemption matching without discarding its finding.
 *
 * @param packageIdentifier - Untrusted Trivy PkgIdentifier field, which may be missing or null.
 * @param installedVersion - Validated installed package version that the PURL must identify.
 * @returns The original PURL if valid and supported, otherwise null. A null PURL
 * prevents exemption matching but does not remove the finding from policy counts.
 */
function eligiblePurl(packageIdentifier, installedVersion) {
    if (packageIdentifier === undefined || packageIdentifier === null)
        return null;
    try {
        return validatePackagePurl(validateObject(packageIdentifier).PURL, installedVersion);
    }
    catch (error) {
        if (error instanceof PolicyError)
            return null;
        throw error;
    }
}
