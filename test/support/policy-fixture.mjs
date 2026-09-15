/** Synthetic immutable Git responses shared by offline runtime adapter tests. */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
export const baseline = JSON.parse(readFileSync(new URL("../fixtures/vulnerability-policy/baseline.json", import.meta.url)));
export const prefix = "/repos/movie-reservation-platform-lab/movie-platform-actions/git/";
export const revision = "1".repeat(40);
export const rootSha = "2".repeat(40);
export const policySha = "3".repeat(40);
export const componentSha = "4".repeat(40);

export function policyFixture(records = baseline.records, component = "recommendation-mcp") {
  const responses = new Map();
  const calls = [];
  const tree = (sha, entries) => ({ sha, truncated: false, tree: entries });
  responses.set(prefix + "ref/heads/main", { ref: "refs/heads/main", object: { type: "commit", sha: revision } });
  responses.set(prefix + `commits/${revision}`, { sha: revision, tree: { sha: rootSha } });
  responses.set(prefix + `trees/${rootSha}`, tree(rootSha, [{ path: "security-exemptions", type: "tree", mode: "040000", sha: policySha }]));
  responses.set(prefix + `trees/${policySha}`, tree(policySha, [{ path: component, type: "tree", mode: "040000", sha: componentSha }]));
  const entries = records.map(record => {
    const bytes = Buffer.from(JSON.stringify(record));
    const sha = createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
    responses.set(prefix + `blobs/${sha}`, { sha, size: bytes.length, encoding: "base64", content: bytes.toString("base64") });
    return { path: `${record.id}.json`, type: "blob", mode: "100644", sha, size: bytes.length };
  });
  responses.set(prefix + `trees/${componentSha}`, tree(componentSha, entries));
  return { responses, calls, read: async (endpoint, limit, deadline) => {
    calls.push({ endpoint, limit, deadline });
    if (!responses.has(endpoint)) throw new Error("Unexpected API request; never reach the network in this test.");
    return structuredClone(responses.get(endpoint));
  } };
}
