/** Bounded, unambiguous documents and exclusive files at runtime trust boundaries. */
import { constants, closeSync, fstatSync, openSync, readSync, realpathSync, writeFileSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";
import { createHash } from "node:crypto";
import { PolicyError } from "./policy-values.mjs";

/** An author-controlled diagnostic safe to display; never wrap raw child-process or I/O messages. */
export class RuntimeError extends Error {}

/** Reject an adapter invariant using a controlled message that safeFailure may display. */
export function requireRuntime(condition: unknown, message: string): asserts condition {
  if (!condition) throw new RuntimeError(message);
}

/** Preserve known policy/adapter diagnostics and replace arbitrary errors that might contain secrets. */
export function safeFailure(error: unknown): string {
  if (error instanceof PolicyError) return `${error.message} Inspect the complete report and selected approvals with the local scanning helper; limits are 128 records, 16 KiB per canonical record, 4,096 result groups, 10,000 findings and 768 KiB per evaluation.`;
  return error instanceof RuntimeError ? error.message : "Container policy operation failed. Check the local scanning runbook; no approval fallback was used.";
}

/** Hash original file bytes using the contract's prefixed SHA-256 representation. */
export function sha256(bytes: Buffer): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

/**
 * Decode strict UTF-8, reject duplicate keys/deep nesting, then parse JSON values.
 * The traversal below checks structure and decoded key identity only. JSON.parse
 * remains the final grammar validator; its reviver also rejects numeric overflow.
 * This distinction lets primitive tokens stay uninterpreted during the traversal.
 */
export function parseJson(bytes: Buffer): unknown {
  let jsonText: string;
  try { jsonText = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { throw new RuntimeError("Document must be valid UTF-8 JSON."); }
  let position = 0;
  const skipWhitespace = () => {
    while (position < jsonText.length && /\s/.test(jsonText[position]!)) position++;
  };
  /** Decode keys so escaped spellings such as "a" and "\u0061" are treated as duplicates. */
  const readJsonString = (): string => {
    const stringStart = position++;
    while (position < jsonText.length) {
      const character = jsonText[position++];
      if (character === "\\") position++;
      else if (character === '"') return JSON.parse(jsonText.slice(stringStart, position)) as string;
    }
    throw new Error();
  };
  const checkJsonValue = (depth: number): void => {
    requireRuntime(depth <= 128, "JSON nesting exceeds limit=128; use the local scanning path to inspect the document.");
    skipWhitespace();
    const openingCharacter = jsonText[position];
    if (openingCharacter === '"') {
      readJsonString();
      return;
    }
    if (openingCharacter === "{" || openingCharacter === "[") {
      position++;
      skipWhitespace();
      const isObject = openingCharacter === "{";
      const closingCharacter = isObject ? "}" : "]";
      const objectKeys = new Set<string>();
      if (jsonText[position] === closingCharacter) {
        position++;
        return;
      }
      while (position < jsonText.length) {
        skipWhitespace();
        if (isObject) {
          if (jsonText[position] !== '"') throw new Error();
          const key = readJsonString();
          requireRuntime(!objectKeys.has(key), "JSON document contains duplicate object keys.");
          objectKeys.add(key);
          skipWhitespace();
          if (jsonText[position++] !== ":") throw new Error();
        }
        checkJsonValue(depth + 1);
        skipWhitespace();
        const separator = jsonText[position++];
        if (separator === closingCharacter) return;
        if (separator !== ",") throw new Error();
      }
      throw new Error();
    }
    // Skip a primitive token here; JSON.parse below validates numbers, booleans and null.
    const tokenStart = position;
    while (position < jsonText.length && !/[\s,\]}]/.test(jsonText[position]!)) position++;
    if (tokenStart === position) throw new Error();
  };
  try {
    checkJsonValue(0);
    skipWhitespace();
    if (position !== jsonText.length) throw new Error();
    return JSON.parse(jsonText, (_key, parsedValue: unknown) => {
      if (typeof parsedValue === "number" && !Number.isFinite(parsedValue)) throw new Error();
      return parsedValue;
    }) as unknown;
  } catch (error) {
    if (error instanceof RuntimeError) throw error;
    throw new RuntimeError("Document must be unambiguous valid JSON.");
  }
}

/**
 * Read a bounded regular file inside root, rejecting final symlinks and hard links.
 * Read one extra byte to detect growth and compare descriptor metadata afterward;
 * a file changed during the read cannot supply evidence bytes.
 */
export function readDocument(root: string, path: string, limit: number, label: string): Buffer {
  const canonicalRoot = realpathSync(root);
  const requestedPath = resolve(canonicalRoot, path);
  const canonicalPath = realpathSync(requestedPath);
  const pathWithinRoot = relative(canonicalRoot, canonicalPath);
  requireRuntime(pathWithinRoot !== "" && pathWithinRoot !== ".." && !pathWithinRoot.startsWith("../") && !isAbsolute(pathWithinRoot), "Document must remain inside its workspace.");
  const descriptor = openSync(requestedPath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(descriptor);
    requireRuntime(before.isFile() && before.nlink === 1, "Document must be a regular file without links.");
    requireRuntime(before.size > 0 && before.size <= limit, `${label} byte limit=${limit}, observed=${before.size}; inspect it using the local scanning path.`);
    const bytes = Buffer.alloc(before.size + 1);
    let bytesRead = 0;
    while (bytesRead < bytes.length) {
      const chunkBytes = readSync(descriptor, bytes, bytesRead, bytes.length - bytesRead, null);
      if (!chunkBytes) break;
      bytesRead += chunkBytes;
    }
    const after = fstatSync(descriptor);
    requireRuntime(bytesRead === before.size && after.size === before.size && after.mtimeMs === before.mtimeMs && after.ctimeMs === before.ctimeMs, "Document changed during its bounded read.");
    return bytes.subarray(0, bytesRead);
  } finally { closeSync(descriptor); }
}

/** Enforce the actual UTF-8 output size including its newline, then create a private file exclusively. */
export function writeJson(path: string, value: unknown, limit: number, label: string): void {
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
  requireRuntime(bytes.length <= limit, `${label} byte limit=${limit}, observed=${bytes.length}; inspect it using the local scanning path.`);
  writeFileSync(path, bytes, { flag: "wx", mode: 0o600 });
}
