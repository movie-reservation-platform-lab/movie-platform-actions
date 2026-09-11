/**
 * Checks untrusted policy fields before callers use them. Invalid input produces
 * controlled error codes, not messages containing the supplied data. These helpers
 * do not read files, fetch URLs, or decide whether an exemption was approved.
 */
export class PolicyError extends Error {
    code;
    constructor(code) {
        super(`Vulnerability policy rejected input: ${code}.`);
        this.code = code;
        this.name = "PolicyError";
    }
}
/**
 * Stops validation when a required condition is falsy.
 * @param condition - Check that must succeed; truthiness is preserved for type narrowing.
 * @param errorCode - Caller-defined diagnostic code, never untrusted input.
 * @throws {PolicyError} If the condition is falsy.
 */
export function assertPolicyCondition(condition, errorCode) {
    if (!condition)
        throw new PolicyError(errorCode);
}
/**
 * Checks that input is a non-null, non-array object, optionally enforcing exact field names.
 *
 * @param untrustedObject - Input to check before reading its fields.
 * @param requiredKeys - If supplied, every listed key must be present and no extra
 * enumerable string keys are allowed. Field values are validated separately.
 * @returns The original object, not a copy; its field values remain untrusted.
 * @throws {PolicyError} If the input is not an object or its field names do not match.
 */
export function validateObject(untrustedObject, requiredKeys) {
    assertPolicyCondition(typeof untrustedObject === "object" && untrustedObject !== null && !Array.isArray(untrustedObject), "invalid-object");
    const record = untrustedObject;
    if (requiredKeys) {
        assertPolicyCondition(Object.keys(record).length === requiredKeys.length && requiredKeys.every((key) => Object.hasOwn(record, key)), "invalid-fields");
    }
    return record;
}
/**
 * Checks nonblank text without trimming it or accepting control characters.
 * @param untrustedText - Input that must be a string with no surrounding whitespace.
 * @param maxCharacters - Maximum Unicode code points allowed; defaults to 2048.
 * @returns The original string, unchanged.
 * @throws {PolicyError} If the string is invalid or too long.
 */
export function validateText(untrustedText, maxCharacters = 2048) {
    assertPolicyCondition(typeof untrustedText === "string" && untrustedText.length > 0 && untrustedText.length <= maxCharacters * 2 && [...untrustedText].length <= maxCharacters &&
        untrustedText === untrustedText.trim() && !/[\u0000-\u001f\u007f\ud800-\udfff]/u.test(untrustedText), "invalid-text");
    return untrustedText;
}
/**
 * Checks that input is an array within the allowed item count.
 * @param untrustedArray - Input to check; its elements are not validated here.
 * @param maxItems - Maximum allowed array length; empty arrays are accepted.
 * @returns The original array, not a copy. Its elements remain untrusted.
 * @throws {PolicyError} If the input is not an array or has too many items.
 */
export function validateArray(untrustedArray, maxItems) {
    assertPolicyCondition(Array.isArray(untrustedArray) && untrustedArray.length <= maxItems, "invalid-list");
    return untrustedArray;
}
/**
 * Parses a whole-second UTC timestamp, rejecting invalid dates and timezone offsets.
 * @param untrustedTimestamp - Timestamp in YYYY-MM-DDTHH:mm:ssZ format.
 * @returns Milliseconds since the Unix epoch.
 * @throws {PolicyError} If the timestamp has invalid text, format, or calendar values.
 */
export function parseUtcTimestamp(untrustedTimestamp) {
    const timestampText = validateText(untrustedTimestamp, 20);
    assertPolicyCondition(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(timestampText), "invalid-time");
    const timestampMs = Date.parse(timestampText);
    assertPolicyCondition(Number.isFinite(timestampMs) && !timestampText.startsWith("0000-") && new Date(timestampMs).toISOString() === timestampText.replace("Z", ".000Z"), "invalid-time");
    return timestampMs;
}
/**
 * Checks an HTTPS reference URL without fetching it or trusting its contents.
 * @param untrustedUrl - URL text; credentials, fragments, and malformed escapes are rejected.
 * @returns The original URL, unchanged rather than normalized.
 * @throws {PolicyError} If the URL fails the reference format checks.
 */
export function validateReferenceUrl(untrustedUrl) {
    const referenceUrl = validateText(untrustedUrl);
    let parsedUrl;
    try {
        parsedUrl = new URL(referenceUrl);
    }
    catch {
        throw new PolicyError("invalid-reference");
    }
    assertPolicyCondition(referenceUrl.startsWith("https://") && /^[\x21-\x7e]+$/.test(referenceUrl) &&
        !referenceUrl.includes("\\") && !referenceUrl.includes("#") && !/%(?![a-fA-F0-9]{2})/.test(referenceUrl) &&
        parsedUrl.protocol === "https:" && !parsedUrl.username && !parsedUrl.password, "invalid-reference");
    return referenceUrl;
}
/**
 * Checks a versioned package URL against the installed version and supported architectures.
 * This accepts the policy's restricted PURL format, not every possible package URL.
 * @param untrustedPurl - Package URL to validate, including any qualifiers.
 * @param installedVersion - Exact installed version, including a Debian epoch when present.
 * @returns The original PURL; decoding is only used for validation, not normalization.
 * @throws {PolicyError} If the PURL is invalid, unsupported, or disagrees with the package version.
 */
export function validatePackagePurl(untrustedPurl, installedVersion) {
    const purl = validateText(untrustedPurl);
    const purlMatch = /^pkg:([a-z][a-z0-9.+-]*)\/([^@?#]+)@([^@?#]+)(?:\?([^#]+))?$/.exec(purl);
    assertPolicyCondition(purlMatch && !/[\s*\\]/u.test(purl), "invalid-purl");
    let decodedVersion;
    const qualifiers = new Map();
    try {
        for (const encodedSegment of purlMatch[2].split("/")) {
            assertPolicyCondition(/^[A-Za-z0-9._~%+-]+$/.test(encodedSegment), "invalid-purl");
            const decodedSegment = decodeURIComponent(encodedSegment);
            assertPolicyCondition(decodedSegment.length > 0 && decodedSegment !== "." && decodedSegment !== ".." && !/[\s*/\\?#\u0000-\u001f\u007f]/u.test(decodedSegment), "invalid-purl");
        }
        assertPolicyCondition(/^[A-Za-z0-9._~%+-]+$/.test(purlMatch[3]), "invalid-purl");
        decodedVersion = decodeURIComponent(purlMatch[3]);
        assertPolicyCondition(decodedVersion.length > 0 && !/[\s*]/u.test(decodedVersion), "invalid-purl");
        for (const encodedQualifier of purlMatch[4]?.split("&") ?? []) {
            const qualifierMatch = /^([a-z][a-z0-9._-]*)=([^=]+)$/.exec(encodedQualifier);
            assertPolicyCondition(qualifierMatch && !qualifiers.has(qualifierMatch[1]), "invalid-purl");
            assertPolicyCondition(/^[A-Za-z0-9._~%+-]+$/.test(qualifierMatch[2]), "invalid-purl");
            const decodedQualifierValue = decodeURIComponent(qualifierMatch[2]);
            assertPolicyCondition(decodedQualifierValue.length > 0 && !/[\s*\u0000-\u001f\u007f]/u.test(decodedQualifierValue), "invalid-purl");
            qualifiers.set(qualifierMatch[1], decodedQualifierValue);
        }
    }
    catch {
        throw new PolicyError("invalid-purl");
    }
    // Trivy represents a Debian epoch separately, e.g. @1.2?epoch=1 for 1:1.2.
    const epoch = qualifiers.get("epoch");
    if (purlMatch[1] === "deb" && epoch !== undefined) {
        assertPolicyCondition(/^(0|[1-9][0-9]*)$/.test(epoch), "invalid-purl");
        decodedVersion = `${epoch}:${decodedVersion}`;
    }
    assertPolicyCondition(decodedVersion === installedVersion, "package-version-mismatch");
    const architecture = qualifiers.get("arch");
    assertPolicyCondition(architecture === undefined || architecture === "amd64" || architecture === "x86_64" || architecture === "all" || architecture === "noarch", "package-platform-mismatch");
    return purl;
}
