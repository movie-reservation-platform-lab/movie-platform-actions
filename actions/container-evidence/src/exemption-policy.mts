/**
 * Validates centrally reviewed exemption records and their time-bounded scope.
 * Checks exemption records, but does not load files or verify who approved them.
 * The caller must supply records from a trusted, reviewed repository revision.
 * Passing these checks alone does not mean an exemption was approved.
 */
import { createHash } from "node:crypto";
import { profileFor } from "./profile.mjs";
import { validateArray, validateObject, validatePackagePurl, validateReferenceUrl, assertPolicyCondition, validateText, parseUtcTimestamp } from "./policy-values.mjs";

export const exemptionRepository = "movie-reservation-platform-lab/movie-platform-actions";
export const maxRecords = 128;
export const maxRecordBytes = 16 * 1024;
export const dayMs = 86_400_000;
export type Component = ReturnType<typeof profileFor>["component"];
export type ExemptionType = "not-affected" | "risk-accepted";
const justifications = [
  "component_not_present",
  "vulnerable_code_not_present",
  "vulnerable_code_not_in_execute_path",
  "vulnerable_code_cannot_be_controlled_by_adversary",
  "inline_mitigations_already_exist",
] as const;
export type Justification = typeof justifications[number];

type Statement = {
  vulnerability: { name: string };
  products: [{ "@id": string; subcomponents: [{ "@id": string }] }];
} & ({ status: "not_affected"; justification: Justification; impact_statement: string }
  | { status: "affected"; action_statement: string });

export type Exemption = {
  apiVersion: "ci.movie-platform.dev/exemptions/v1alpha1";
  id: string;
  component: Component;
  type: ExemptionType;
  package: { name: string; version: string; purl: string };
  platform: { os: "linux"; architecture: "amd64" };
  owner: string;
  createdAt: string;
  approval: { by: string; at: string; reference: string };
  expiresAt: string;
  rationale: string;
  references: string[];
  vex: { "@context": "https://openvex.dev/ns/v0.2.0"; "@id": string; author: string; timestamp: string; version: number; statements: [Statement] };
};

/**
 * Checks that a component is enrolled and returns its known profile name.
 *
 * @param untrustedComponentName - Component name to validate, not a repository name or URL.
 * @returns An enrolled component name.
 * @throws {PolicyError} If the name is invalid or not supported.
 */
export function componentName(untrustedComponentName: unknown): Component {
  const component = validateText(untrustedComponentName, 64);
  // TODO(component-onboarding): centralize these lists and profile mappings.
  // Tracked in https://github.com/movie-reservation-platform-lab/movie-platform-actions/issues/10.
  assertPolicyCondition(["reservation-service", "reservation-agent", "recommendation-service", "reservation-mcp", "recommendation-mcp", "reservation-web"].includes(component), "unsupported-component");
  return profileFor(component).component;
}

/**
 * Checks a record's identity, package, approval window, and matching VEX statement.
 * Expired records can still be parsed; whether they can be used is checked during evaluation.
 *
 * @param untrustedRecord - Parsed exemption JSON whose fields have not yet been validated.
 * @returns A validated copy, detached from the caller's record. Validation is not proof of approval.
 * @throws {PolicyError} If fields are missing, unexpected, inconsistent, or exceed allowed limits.
 */
export function parseExemption(untrustedRecord: unknown): Exemption {
  const record = validateObject(untrustedRecord, [
    "apiVersion", "id", "component", "type", "package", "platform", "owner",
    "createdAt", "approval", "expiresAt", "rationale", "references", "vex",
  ]);
  const identity = validateExemptionIdentity(record);
  const purl = validatePackageScope(record);
  const approval = validateApproval(record, identity.type);
  validateVex(record.vex, identity, purl, approval);
  assertPolicyCondition(Buffer.byteLength(JSON.stringify(untrustedRecord), "utf8") <= maxRecordBytes, "record-too-large");
  // All required fields and their relationships have been checked; preserve the original data.
  return structuredClone(untrustedRecord) as Exemption;
}

/**
 * Checks the record version, ID, enrolled component, and exemption type.
 * @param record - Exemption object with its top-level field names already checked.
 * @returns Validated identity fields used to cross-check the VEX statement.
 */
function validateExemptionIdentity(record: Record<string, unknown>): { id: string; component: Component; type: ExemptionType } {
  assertPolicyCondition(record.apiVersion === "ci.movie-platform.dev/exemptions/v1alpha1", "unsupported-exemption-version");
  const id = validateText(record.id, 64);
  assertPolicyCondition(/^EX-[A-Za-z0-9][A-Za-z0-9-]{0,60}$/.test(id), "invalid-exemption-id");
  const component = componentName(record.component);
  assertPolicyCondition(record.type === "not-affected" || record.type === "risk-accepted", "unsupported-exemption-type");
  return { id, component, type: record.type };
}

/**
 * Checks the exact package identity and supported linux/amd64 platform.
 * @param record - Exemption object containing untrusted package and platform fields.
 * @returns The validated PURL, preserved exactly for matching against the VEX product.
 */
function validatePackageScope(record: Record<string, unknown>): string {
  const pkg = validateObject(record.package, ["name", "version", "purl"]);
  validateText(pkg.name, 256);
  const version = validateText(pkg.version, 256);
  const purl = validatePackagePurl(pkg.purl, version);
  const platform = validateObject(record.platform, ["os", "architecture"]);
  assertPolicyCondition(platform.os === "linux" && platform.architecture === "amd64", "unsupported-platform");
  return purl;
}

/**
 * Checks ownership, supporting references, and the approval's allowed 30/90-day window.
 * @param record - Exemption object containing untrusted governance fields.
 * @param exemptionType - Validated type that determines the maximum approval duration.
 * @returns Approver and approval timestamp for comparison with the VEX author and timestamp.
 */
function validateApproval(record: Record<string, unknown>, exemptionType: ExemptionType) {
  validateText(record.owner, 256);
  validateText(record.rationale);
  const references = validateArray(record.references, 8).map(validateReferenceUrl);
  assertPolicyCondition(references.length > 0 && new Set(references).size === references.length, "invalid-references");
  const approval = validateObject(record.approval, ["by", "at", "reference"]);
  const approver = validateText(approval.by, 256);
  const approvalRef = validateReferenceUrl(approval.reference);
  assertPolicyCondition(/^https:\/\/github\.com\/movie-reservation-platform-lab\/movie-platform-actions\/pull\/[1-9][0-9]*$/.test(approvalRef), "invalid-approval-reference");
  const created = parseUtcTimestamp(record.createdAt);
  const approved = parseUtcTimestamp(approval.at);
  const expires = parseUtcTimestamp(record.expiresAt);
  const maxDays = exemptionType === "risk-accepted" ? 30 : 90;
  assertPolicyCondition(created <= approved && expires > approved && expires - approved <= maxDays * dayMs, "invalid-lifetime");
  return { approver, approvedAt: approval.at };
}

/**
 * Checks that the VEX document describes this exemption and the same approval decision.
 * @param untrustedVex - Embedded VEX document before validation.
 * @param identity - Validated exemption ID, component, and type.
 * @param purl - Validated package URL that the statement must reference exactly.
 * @param approval - Validated approver and timestamp that the VEX document must repeat.
 */
function validateVex(
  untrustedVex: unknown,
  identity: ReturnType<typeof validateExemptionIdentity>,
  purl: string,
  approval: ReturnType<typeof validateApproval>,
): void {
  const vex = validateObject(untrustedVex, ["@context", "@id", "author", "timestamp", "version", "statements"]);
  assertPolicyCondition(vex["@context"] === "https://openvex.dev/ns/v0.2.0" && vex["@id"] === `urn:movie-platform:exemption:${identity.id}`, "invalid-vex-identity");
  assertPolicyCondition(vex.author === approval.approver && vex.timestamp === approval.approvedAt, "vex-approval-mismatch");
  assertPolicyCondition(Number.isSafeInteger(vex.version) && Number(vex.version) > 0, "invalid-vex-version");
  const statements = validateArray(vex.statements, 1);
  assertPolicyCondition(statements.length === 1, "invalid-vex-statements");
  validateVexStatement(statements[0], identity, purl);
}

/**
 * Checks the single CVE/product pair and the explanation required by the exemption type.
 * @param untrustedStatement - VEX statement before validation.
 * @param identity - Validated component and type that the statement must describe.
 * @param purl - Exact validated package URL expected in the product's subcomponent.
 */
function validateVexStatement(
  untrustedStatement: unknown,
  identity: ReturnType<typeof validateExemptionIdentity>,
  purl: string,
): void {
  const statusKeys = identity.type === "not-affected" ? ["status", "justification", "impact_statement"] : ["status", "action_statement"];
  const statement = validateObject(untrustedStatement, ["vulnerability", "products", ...statusKeys]);
  const vulnerability = validateObject(statement.vulnerability, ["name"]);
  assertPolicyCondition(/^CVE-[0-9]{4}-[0-9]{4,}$/.test(validateText(vulnerability.name, 64)), "invalid-vulnerability-id");
  const products = validateArray(statement.products, 1);
  assertPolicyCondition(products.length === 1, "invalid-vex-product");
  const product = validateObject(products[0], ["@id", "subcomponents"]);
  assertPolicyCondition(product["@id"] === `https://github.com/${profileFor(identity.component).repository}`, "component-product-mismatch");
  const subcomponents = validateArray(product.subcomponents, 1);
  assertPolicyCondition(subcomponents.length === 1 && validateObject(subcomponents[0], ["@id"])["@id"] === purl, "package-product-mismatch");
  if (identity.type === "not-affected") {
    assertPolicyCondition(statement.status === "not_affected" && justifications.some((justification) => justification === statement.justification), "invalid-justification");
    validateText(statement.impact_statement);
  } else {
    assertPolicyCondition(statement.status === "affected", "risk-status-mismatch");
    validateText(statement.action_statement);
  }
}

/** Sorts closed JSON object keys for cross-language identity; array order is preserved. */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`).join(",")}}`;
  }
  assertPolicyCondition(value === null || typeof value === "string" || typeof value === "boolean" || (typeof value === "number" && Number.isSafeInteger(value)), "invalid-json-value");
  return JSON.stringify(value);
}

/** Hashes validated semantic record content, ignoring whitespace and object key order. */
export function exemptionDigest(record: Exemption): string {
  return `sha256:${createHash("sha256").update(canonicalJson(parseExemption(record)), "utf8").digest("hex")}`;
}

/** Rejects ambiguous approval IDs or CVE/PURL scope within a selected component. */
export function parseExemptions(values: unknown, component: Component): Exemption[] {
  componentName(component);
  const records = validateArray(values, maxRecords).map(parseExemption);
  const ids = new Set<string>();
  const scopes = new Set<string>();
  for (const record of records) {
    assertPolicyCondition(record.component === component, "wrong-component-record");
    const scope = `${record.vex.statements[0].vulnerability.name}\n${record.package.purl}`;
    assertPolicyCondition(!ids.has(record.id) && !scopes.has(scope), "conflicting-exemptions");
    ids.add(record.id);
    scopes.add(scope);
  }
  return records;
}

/** Rechecks used approvals against a separately trusted snapshot and the current clock. */
export function verifyExemptionSnapshot(used: unknown, trusted: unknown, component: Component, now: string): void {
  const time = parseUtcTimestamp(now);
  const approved = new Map(parseExemptions(trusted, component).map((record) => [record.id, exemptionDigest(record)]));
  for (const record of parseExemptions(used, component)) {
    assertPolicyCondition(approved.get(record.id) === exemptionDigest(record), "withdrawn-or-changed-exemption");
    assertPolicyCondition(parseUtcTimestamp(record.approval.at) <= time && time < parseUtcTimestamp(record.expiresAt), "exemption-not-current");
  }
}
