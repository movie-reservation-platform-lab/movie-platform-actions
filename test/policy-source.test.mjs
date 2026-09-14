import { test, mock } from "node:test";
import assert from "node:assert/strict";
import https from "node:https";
import { syncBuiltinESMExports } from "node:module";
import { EventEmitter } from "node:events";
import { performance } from "node:perf_hooks";
import { acquirePolicy, githubPolicyReader } from "../actions/container-evidence/lib/policy-source.mjs";
import { parseJson } from "../actions/container-evidence/lib/runtime-files.mjs";
import { baseline, policyFixture, prefix, revision, rootSha, policySha, componentSha } from "./support/policy-fixture.mjs";

test("acquisition freezes one approved main and validates exact record bytes", async () => {
  const f = policyFixture();
  const snapshot = await acquirePolicy("recommendation-mcp", f.read);
  assert.equal(snapshot.revision, revision);
  assert.deepEqual(snapshot.records, baseline.records);
  assert.equal(f.calls.filter(call => call.endpoint.endsWith("ref/heads/main")).length, 1);
  assert.equal(new Set(f.calls.map(call => call.deadline)).size, 1);
  assert.equal(f.calls.length, 6);
  assert.ok(f.calls.every(call => call.endpoint.startsWith(prefix)));
  assert.equal(f.calls.at(-1).limit, 128 * 1024);
});

test("complete component absence establishes empty policy without reading other components", async () => {
  const f = policyFixture();
  const policy = f.responses.get(prefix + `trees/${policySha}`);
  policy.tree[0].path = "reservation-web";
  assert.deepEqual((await acquirePolicy("recommendation-mcp", f.read)).records, []);
  assert.equal(f.calls.length, 4);
});

const treeKey = prefix + `trees/${componentSha}`;
const scenarios = {
  "wrong ref": f => { f.responses.get(prefix + "ref/heads/main").ref = "refs/heads/unreviewed"; },
  "missing revision": f => { delete f.responses.get(prefix + "ref/heads/main").object.sha; },
  "wrong commit": f => { f.responses.get(prefix + `commits/${revision}`).sha = "f".repeat(40); },
  "missing root": f => { f.responses.get(prefix + `trees/${rootSha}`).tree = []; },
  "truncated parent cannot prove absence": f => { Object.assign(f.responses.get(prefix + `trees/${policySha}`), { tree: [], truncated: true }); },
  "symlink directory": f => { f.responses.get(prefix + `trees/${rootSha}`).tree[0].mode = "120000"; },
  "wrong tree identity": f => { f.responses.get(treeKey).sha = "f".repeat(40); },
  "truncated component": f => { f.responses.get(treeKey).truncated = true; },
  "duplicate member": f => { f.responses.get(treeKey).tree.push(f.responses.get(treeKey).tree[0]); },
  "unsafe name": f => { f.responses.get(treeKey).tree[0].path = "../EX-OTHER.json"; },
  "nested directory": f => { f.responses.get(treeKey).tree[0].type = "tree"; },
  "executable record": f => { f.responses.get(treeKey).tree[0].mode = "100755"; },
  "symlink record": f => { f.responses.get(treeKey).tree[0].mode = "120000"; },
  "nonrecord file": f => { f.responses.get(treeKey).tree[0].path = "README.md"; },
  "raw size": f => { f.responses.get(treeKey).tree[0].size = 65537; },
  "filename disagrees with ID": f => { f.responses.get(treeKey).tree[0].path = "EX-OTHER.json"; },
  "changed blob bytes": f => { const key = [...f.responses.keys()].find(key => key.includes("/blobs/")); f.responses.get(key).content = Buffer.from("{}").toString("base64"); },
  "wrong blob identity": f => { const key = [...f.responses.keys()].find(key => key.includes("/blobs/")); f.responses.get(key).sha = "f".repeat(40); },
  "invalid base64": f => { const key = [...f.responses.keys()].find(key => key.includes("/blobs/")); f.responses.get(key).content += "!"; },
  "record count limit": f => { f.responses.get(treeKey).tree = Array.from({ length: 129 }, (_, i) => ({ ...f.responses.get(treeKey).tree[0], path: `EX-${i}.json` })); },
  "tree count limit": f => { f.responses.get(treeKey).tree = Array.from({ length: 4097 }, (_, i) => ({ path: `EX-${i}.json` })); },
};
for (const [name, change] of Object.entries(scenarios)) test(`acquisition rejects ${name} without fallback`, async () => {
  const f = policyFixture();
  change(f);
  await assert.rejects(acquirePolicy("recommendation-mcp", f.read));
});

test("any failed request prevents an empty/stale snapshot", async () => {
  for (let failure = 0; failure < 6; failure++) {
    const f = policyFixture();
    let count = 0;
    await assert.rejects(acquirePolicy("recommendation-mcp", async (...args) => {
      if (count++ === failure) throw new Error("Transport failure");
      return f.read(...args);
    }));
    assert.equal(count, failure + 1);
  }
});

test("malformed/conflicting selected records fail; expired records remain available", async () => {
  for (const mutate of [r => { delete r.owner; }, r => { r.component = "reservation-web"; }]) {
    const records = structuredClone(baseline.records);
    mutate(records[0]);
    await assert.rejects(acquirePolicy("recommendation-mcp", policyFixture(records).read));
  }
  const duplicate = structuredClone(baseline.records[0]);
  duplicate.id = "EX-DUPLICATE";
  duplicate.vex["@id"] = `urn:movie-platform:exemption:${duplicate.id}`;
  await assert.rejects(acquirePolicy("recommendation-mcp", policyFixture([...baseline.records, duplicate]).read));
  const expired = structuredClone(baseline.records[0]);
  expired.expiresAt = "2026-09-02T00:00:00Z";
  assert.equal((await acquirePolicy("recommendation-mcp", policyFixture([expired]).read)).records.length, 1);
});

for (const text of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"x":[{"a":1,"a":2}]}', '{"x":NaN}', '{"x":1e999}', '\ufeff{}', '['.repeat(130) + ']'.repeat(130)]) {
  test("strict JSON rejects ambiguous, non-finite or excessive documents: " + text.slice(0, 35), () => assert.throws(() => parseJson(Buffer.from(text))));
}
test("strict JSON permits escaped strings and identical keys in separate objects", () => {
  const value = [{ a: 'a"\\b' }, { a: [1, true, null, {}] }];
  assert.deepEqual(parseJson(Buffer.from(JSON.stringify(value))), value);
  assert.throws(() => parseJson(Buffer.from([0xff])));
});

test("HTTPS transport fixes authority, credentials, response bounds and failure handling", async () => {
  let mode = "ok";
  const requests = [];
  mock.method(https, "request", (options, callback) => {
    requests.push(options);
    const req = new EventEmitter();
    req.destroy = error => { queueMicrotask(() => { req.emit("error", error); req.emit("close"); }); return req; };
    req.end = () => queueMicrotask(() => {
      if (mode === "timeout") return;
      const response = new EventEmitter();
      response.statusCode = mode === "redirect" ? 302 : mode === "denied" ? 403 : 200;
      callback(response);
      if (response.statusCode === 200) {
        response.emit("data", Buffer.from(mode === "large" ? "x".repeat(101) : '{"ok":true}'));
        response.emit("end");
        req.emit("close");
      }
    });
    return req;
  });
  syncBuiltinESMExports();
  try {
    const reader = githubPolicyReader("TOKEN_SENTINEL");
    assert.deepEqual(await reader(prefix + "ref/heads/main", 100, performance.now() + 1000), { ok: true });
    assert.equal(requests[0].hostname, "api.github.com");
    assert.equal(requests[0].headers.Authorization, "Bearer TOKEN_SENTINEL");
    assert.equal(requests[0].rejectUnauthorized, true);
    assert.equal(requests[0].agent, false);
    await assert.rejects(reader("https://evil.test", 100, performance.now() + 1000));
    for (mode of ["redirect", "denied", "large", "timeout"]) {
      await assert.rejects(reader(prefix + "ref/heads/main", 100, performance.now() + (mode === "timeout" ? 10 : 1000)), error => !error.message.includes("TOKEN_SENTINEL"));
    }
    assert.throws(() => githubPolicyReader(undefined));
    assert.throws(() => githubPolicyReader("bad\nheader"));
  } finally { mock.restoreAll(); syncBuiltinESMExports(); }
});
