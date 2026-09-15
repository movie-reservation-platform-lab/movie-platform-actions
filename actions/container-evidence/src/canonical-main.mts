/** Authenticated, bounded lookup of a reviewed component's exact main ref. */
import { request } from "node:https";
import type { ClientRequest, IncomingMessage } from "node:http";
import { performance } from "node:perf_hooks";
import { profileFor } from "./profile.mjs";
import { parseJson } from "./runtime-files.mjs";

const requestTimeoutMs = 30_000;
const maxResponseBytes = 4096;

export type CanonicalMainFailureCode =
  | "invalid-github-token"
  | "canonical-main-unavailable"
  | "canonical-main-timeout"
  | "canonical-main-response-too-large"
  | "canonical-main-invalid-response";

/** Only this closed code crosses the transport boundary; raw errors stay private. */
export class CanonicalMainError extends Error {
  constructor(readonly code: CanonicalMainFailureCode) {
    super(code);
    this.name = "CanonicalMainError";
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Extra GitHub metadata is harmless; the exact ref and commit identity are required. */
function canonicalCommitSha(bytes: Buffer): string {
  try {
    const reference = parseJson(bytes);
    if (
      isObject(reference) && reference.ref === "refs/heads/main" &&
      isObject(reference.object) && reference.object.type === "commit" &&
      typeof reference.object.sha === "string" && /^[a-f0-9]{40}$/.test(reference.object.sha)
    ) return reference.object.sha;
  } catch { /* Parser diagnostics are not part of the prepare interface. */ }
  throw new CanonicalMainError("canonical-main-invalid-response");
}

/** One request; the deadline covers connection setup and the complete response. */
export async function resolveCanonicalMain(component: string | undefined, token: string | undefined): Promise<string> {
  const repository = profileFor(component).repository;
  if (typeof token !== "string" || !/^[\x21-\x7e]{1,4096}$/.test(token)) {
    throw new CanonicalMainError("invalid-github-token");
  }
  const deadline = performance.now() + requestTimeoutMs;
  const bytes = await new Promise<Buffer>((resolve, reject) => {
    let clientRequest: ClientRequest | undefined;
    let response: IncomingMessage | undefined;
    let settled = false;
    let receivedBytes = 0;
    const chunks: Buffer[] = [];
    const timer = setTimeout(() => fail("canonical-main-timeout"), requestTimeoutMs);

    function fail(code: CanonicalMainFailureCode): void {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      chunks.length = 0;
      response?.destroy();
      clientRequest?.destroy();
      reject(new CanonicalMainError(code));
    }

    try {
      clientRequest = request({
        hostname: "api.github.com", port: 443, method: "GET",
        path: `/repos/${repository}/git/ref/heads/main`,
        agent: false, rejectUnauthorized: true, maxHeaderSize: 16 * 1024,
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/vnd.github+json",
          "User-Agent": "movie-platform-actions",
          "X-GitHub-Api-Version": "2022-11-28",
        },
      }, (incoming) => {
        response = incoming;
        // Handle errors before a rejection destroys the response stream.
        incoming.on("error", () => fail("canonical-main-unavailable"));
        incoming.on("close", () => {
          if (!incoming.complete) fail("canonical-main-unavailable");
        });
        if (settled) { incoming.destroy(); return; }
        if (incoming.statusCode !== 200) { fail("canonical-main-unavailable"); return; }
        const encoding = incoming.headers["content-encoding"];
        if (encoding !== undefined && encoding !== "identity") {
          fail("canonical-main-invalid-response");
          return;
        }
        incoming.on("data", (chunk: Buffer) => {
          if (settled) return;
          receivedBytes += chunk.length;
          if (receivedBytes > maxResponseBytes) fail("canonical-main-response-too-large");
          else chunks.push(chunk);
        });
        incoming.on("end", () => {
          if (settled) return;
          if (!incoming.complete) { fail("canonical-main-unavailable"); return; }
          if (performance.now() >= deadline) { fail("canonical-main-timeout"); return; }
          settled = true;
          clearTimeout(timer);
          resolve(Buffer.concat(chunks, receivedBytes));
          chunks.length = 0;
        });
      });
      clientRequest.on("error", () => fail("canonical-main-unavailable"));
      clientRequest.on("close", () => {
        if (!settled) fail("canonical-main-unavailable");
      });
      clientRequest.end();
    } catch { fail("canonical-main-unavailable"); }
  });
  const sha = canonicalCommitSha(bytes);
  if (performance.now() >= deadline) throw new CanonicalMainError("canonical-main-timeout");
  return sha;
}
