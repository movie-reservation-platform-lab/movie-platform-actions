/** Bounded, unambiguous documents and exclusive files at runtime trust boundaries. */
import { constants, closeSync, fstatSync, openSync, readSync, realpathSync, writeFileSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";
import { createHash } from "node:crypto";
import { PolicyError } from "./policy-values.mjs";
export class RuntimeError extends Error {
}
export function requireRuntime(condition, message) {
    if (!condition)
        throw new RuntimeError(message);
}
export function safeFailure(error) {
    if (error instanceof PolicyError)
        return `${error.message} Inspect the complete report and selected approvals with the local scanning helper; limits are 128 records, 16 KiB per canonical record, 4,096 result groups, 10,000 findings and 768 KiB per evaluation.`;
    return error instanceof RuntimeError ? error.message : "Container policy operation failed. Check the local scanning runbook; no approval fallback was used.";
}
export function sha256(bytes) {
    return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}
/** Reject duplicate keys and excessive nesting before using JSON.parse's value semantics. */
export function parseJson(bytes) {
    let text;
    try {
        text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    }
    catch {
        throw new RuntimeError("Document must be valid UTF-8 JSON.");
    }
    let position = 0;
    const space = () => { while (/\s/.test(text[position] ?? "") && position < text.length)
        position++; };
    const string = () => {
        const start = position++;
        while (position < text.length) {
            const char = text[position++];
            if (char === "\\")
                position++;
            else if (char === '"')
                return JSON.parse(text.slice(start, position));
        }
        throw new Error();
    };
    const value = (depth) => {
        requireRuntime(depth <= 128, "JSON nesting exceeds limit=128; use the local scanning path to inspect the document.");
        space();
        const char = text[position];
        if (char === '"') {
            string();
            return;
        }
        if (char === "{" || char === "[") {
            position++;
            space();
            const end = char === "{" ? "}" : "]";
            const keys = new Set();
            if (text[position] === end) {
                position++;
                return;
            }
            while (position < text.length) {
                space();
                if (char === "{") {
                    if (text[position] !== '"')
                        throw new Error();
                    const key = string();
                    requireRuntime(!keys.has(key), "JSON document contains duplicate object keys.");
                    keys.add(key);
                    space();
                    if (text[position++] !== ":")
                        throw new Error();
                }
                value(depth + 1);
                space();
                const separator = text[position++];
                if (separator === end)
                    return;
                if (separator !== ",")
                    throw new Error();
            }
            throw new Error();
        }
        const start = position;
        while (position < text.length && !/[\s,\]}]/.test(text[position]))
            position++;
        if (start === position)
            throw new Error();
    };
    try {
        value(0);
        space();
        if (position !== text.length)
            throw new Error();
        return JSON.parse(text, (_key, parsed) => {
            if (typeof parsed === "number" && !Number.isFinite(parsed))
                throw new Error();
            return parsed;
        });
    }
    catch (error) {
        if (error instanceof RuntimeError)
            throw error;
        throw new RuntimeError("Document must be unambiguous valid JSON.");
    }
}
/** Resolve containment and bound bytes from a regular, non-symlink descriptor. */
export function readDocument(root, path, limit, label) {
    const canonicalRoot = realpathSync(root);
    const requested = resolve(canonicalRoot, path);
    const canonical = realpathSync(requested);
    const within = relative(canonicalRoot, canonical);
    requireRuntime(within !== "" && within !== ".." && !within.startsWith("../") && !isAbsolute(within), "Document must remain inside its workspace.");
    const descriptor = openSync(requested, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
        const before = fstatSync(descriptor);
        requireRuntime(before.isFile() && before.nlink === 1, "Document must be a regular file without links.");
        requireRuntime(before.size > 0 && before.size <= limit, `${label} byte limit=${limit}, observed=${before.size}; inspect it using the local scanning path.`);
        const bytes = Buffer.alloc(before.size + 1);
        let length = 0;
        while (length < bytes.length) {
            const read = readSync(descriptor, bytes, length, bytes.length - length, null);
            if (!read)
                break;
            length += read;
        }
        const after = fstatSync(descriptor);
        requireRuntime(length === before.size && after.size === before.size && after.mtimeMs === before.mtimeMs && after.ctimeMs === before.ctimeMs, "Document changed during its bounded read.");
        return bytes.subarray(0, length);
    }
    finally {
        closeSync(descriptor);
    }
}
export function writeJson(path, value, limit, label) {
    const bytes = Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
    requireRuntime(bytes.length <= limit, `${label} byte limit=${limit}, observed=${bytes.length}; inspect it using the local scanning path.`);
    writeFileSync(path, bytes, { flag: "wx", mode: 0o600 });
}
