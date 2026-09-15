import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { syncBuiltinESMExports } from "node:module";
import { spawnSync } from "node:child_process";
import { resolveCanonicalMain } from "../actions/container-evidence/lib/canonical-main.mjs";
import { prepareCandidate, preparationFailure } from "../actions/container-evidence/lib/prepare.mjs";
import { profileFor } from "../actions/container-evidence/lib/profile.mjs";
import { installGithubMock, mainReference, sourceSha } from "./support/prepare-http-fixture.mjs";

const token = "TOKEN_SENTINEL";
const components = ["reservation-service", "reservation-agent", "recommendation-service", "reservation-mcp", "recommendation-mcp", "reservation-web"];

function githubMock(t, scenario) {
  const requests = installGithubMock(t.mock, scenario);
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
  return requests;
}

function publicationFixture(t, component = "recommendation-mcp") {
  const directory = mkdtempSync(join(tmpdir(), "prepare-test-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const profile = profileFor(component);
  const env = {
    COMPONENT: component, GH_TOKEN: token,
    GITHUB_REPOSITORY: profile.repository, GITHUB_REF: "refs/heads/main",
    GITHUB_EVENT_NAME: "push", GITHUB_JOB: profile.jobId,
    GITHUB_SERVER_URL: "https://github.com", GITHUB_API_URL: "https://api.github.com",
    GITHUB_SHA: sourceSha, GITHUB_RUN_ID: "123", GITHUB_RUN_ATTEMPT: "2",
    GITHUB_OUTPUT: join(directory, "output"),
  };
  return { directory, profile, env };
}

const rejectsWith = (code) => (error) => {
  assert.match(preparationFailure(error), new RegExp(`\\] ${code}:`));
  assert.doesNotMatch(preparationFailure(error), /TOKEN_SENTINEL|BODY_SENTINEL|TRANSPORT_SENTINEL/);
  return true;
};

for (const component of components) {
  test(`${component}: matching main uses authenticated fixed API and writes exact discovery outputs`, async (t) => {
    const { env, profile } = publicationFixture(t, component);
    const requests = githubMock(t);
    await prepareCandidate(env);
    assert.equal(requests.length, 1);
    assert.deepEqual(requests[0].options, {
      hostname: "api.github.com", port: 443, method: "GET",
      path: `/repos/${profile.repository}/git/ref/heads/main`,
      agent: false, rejectUnauthorized: true, maxHeaderSize: 16 * 1024,
      headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json",
        "User-Agent": "movie-platform-actions", "X-GitHub-Api-Version": "2022-11-28" },
    });
    assert.equal(readFileSync(env.GITHUB_OUTPUT, "utf8"),
      `image_ref=${profile.image}\ntag=${profile.tagPrefix}-${sourceSha}-run-123-attempt-2\nartifact=${component}-security-evidence-123-attempt-2\n`);
  });
}

for (const [label, invalidToken] of [
  ["missing", undefined], ["empty", ""], ["spaces", " "], ["newline", "secret\nheader"],
  ["control", "secret\0"], ["non-ASCII", "tökén"], ["too long", "t".repeat(4097)],
]) {
  test(`token ${label}: rejects before an API request`, async (t) => {
    const requests = githubMock(t);
    await assert.rejects(resolveCanonicalMain("recommendation-mcp", invalidToken), rejectsWith("invalid-github-token"));
    assert.equal(requests.length, 0);
  });
}

for (const [key, value] of Object.entries({
  COMPONENT: "unreviewed", GITHUB_REPOSITORY: "another/repository", GITHUB_REF: "refs/heads/topic",
  GITHUB_EVENT_NAME: "pull_request", GITHUB_JOB: "other-job", GITHUB_SHA: "bad-sha",
  GITHUB_RUN_ID: "0", GITHUB_RUN_ATTEMPT: "1.5", GITHUB_SERVER_URL: "https://elsewhere.test",
  GITHUB_API_URL: "https://elsewhere.test",
})) {
  test(`invalid ${key}: rejects before network and preserves existing outputs`, async (t) => {
    const { env } = publicationFixture(t);
    env[key] = value;
    writeFileSync(env.GITHUB_OUTPUT, "earlier_step=preserved\n");
    const requests = githubMock(t);
    await assert.rejects(prepareCandidate(env), rejectsWith("invalid-publication-context"));
    assert.equal(requests.length, 0);
    assert.equal(readFileSync(env.GITHUB_OUTPUT, "utf8"), "earlier_step=preserved\n");
  });
}

test("missing API environment fails even with a valid token", async (t) => {
  const { env } = publicationFixture(t);
  delete env.GITHUB_API_URL;
  const requests = githubMock(t);
  await assert.rejects(prepareCandidate(env), rejectsWith("invalid-publication-context"));
  assert.equal(requests.length, 0);
});

for (const status of [201, 301, 302, 401, 403, 404, 429, 500, 503]) {
  test(`HTTP ${status}: no accepted body, redirect, retry or output`, async (t) => {
    const { env } = publicationFixture(t);
    const requests = githubMock(t, { status, body: "BODY_SENTINEL" });
    await assert.rejects(prepareCandidate(env), rejectsWith("canonical-main-unavailable"));
    assert.equal(requests.length, 1);
    assert.equal(requests[0].request.destroyed, true);
    assert.equal(requests[0].response.destroyed, true);
    assert.equal(existsSync(env.GITHUB_OUTPUT), false);
  });
}

const invalidBodies = [
  ["empty", ""], ["invalid JSON", "BODY_SENTINEL"], ["invalid UTF-8", Buffer.from([0xff])],
  ["null", "null"], ["primitive", "42"], ["array", JSON.stringify([mainReference()])],
  ["missing ref", JSON.stringify({ object: mainReference().object })],
  ["wrong ref", JSON.stringify({ ...mainReference(), ref: "refs/heads/main-extra" })],
  ["missing target", JSON.stringify({ ref: "refs/heads/main" })],
  ["tag target", JSON.stringify({ ref: "refs/heads/main", object: { type: "tag", sha: sourceSha } })],
  ["short SHA", JSON.stringify(mainReference("abc"))],
  ["uppercase SHA", JSON.stringify(mainReference("B".repeat(40)))],
  ["duplicate SHA", `{"ref":"refs/heads/main","object":{"type":"commit","sha":"${sourceSha}","sha":"${sourceSha}"}}`],
];
for (const [label, body] of invalidBodies) {
  test(`response ${label}: refuses ambiguous or malformed canonical identity`, async (t) => {
    const { env } = publicationFixture(t);
    githubMock(t, { body });
    await assert.rejects(prepareCandidate(env), rejectsWith("canonical-main-invalid-response"));
    assert.equal(existsSync(env.GITHUB_OUTPUT), false);
  });
}

test("additive response fields are allowed but returned URLs are never followed", async (t) => {
  const requests = githubMock(t, { body: JSON.stringify({ ...mainReference(), url: "https://elsewhere.test", node_id: "metadata" }) });
  assert.equal(await resolveCanonicalMain("recommendation-mcp", token), sourceSha);
  assert.equal(requests.length, 1);
});

for (const size of [4096, 4097]) {
  test(`response bound: ${size} actual bytes despite a misleading Content-Length`, async (t) => {
    const body = JSON.stringify(mainReference()).padEnd(size, " ");
    const requests = githubMock(t, { chunks: [body.slice(0, 100), body.slice(100)], headers: { "content-length": "1" } });
    const lookup = resolveCanonicalMain("recommendation-mcp", token);
    if (size === 4096) assert.equal(await lookup, sourceSha);
    else {
      await assert.rejects(lookup, rejectsWith("canonical-main-response-too-large"));
      assert.equal(requests[0].request.destroyed, true);
    }
  });
}

test("unexpected compression is refused without decompression", async (t) => {
  githubMock(t, { headers: { "content-encoding": "gzip" } });
  await assert.rejects(resolveCanonicalMain("recommendation-mcp", token), rejectsWith("canonical-main-invalid-response"));
});

for (const failure of ["throw", "request", "response", "incomplete"]) {
  test(`transport ${failure}: generic error without private diagnostics`, async (t) => {
    const { env } = publicationFixture(t);
    githubMock(t, { failure });
    await assert.rejects(prepareCandidate(env), rejectsWith("canonical-main-unavailable"));
    assert.equal(existsSync(env.GITHUB_OUTPUT), false);
  });
}

for (const failure of ["no-headers", "stalled-body"]) {
  test(`${failure}: one total 30-second deadline destroys request and ignores late success`, async (t) => {
    const { env } = publicationFixture(t);
    const requests = githubMock(t, { failure, chunks: [] });
    t.mock.timers.enable({ apis: ["setTimeout"] });
    const rejection = assert.rejects(prepareCandidate(env), rejectsWith("canonical-main-timeout"));
    await Promise.resolve();
    t.mock.timers.tick(20_000);
    if (failure === "stalled-body") requests[0].response.emit("data", Buffer.from(" "));
    t.mock.timers.tick(9_999);
    assert.equal(requests[0].request.destroyed, false);
    t.mock.timers.tick(1);
    await rejection;
    assert.equal(requests.length, 1);
    assert.equal(requests[0].request.destroyed, true);
    requests[0].response.complete = true;
    requests[0].response.emit("data", Buffer.from(JSON.stringify(mainReference())));
    requests[0].response.emit("end");
    assert.equal(existsSync(env.GITHUB_OUTPUT), false);
  });
}

test("stale main leaves outputs unchanged", async (t) => {
  const { env } = publicationFixture(t);
  writeFileSync(env.GITHUB_OUTPUT, "earlier_step=preserved\n");
  githubMock(t, { body: JSON.stringify(mainReference("c".repeat(40))) });
  await assert.rejects(prepareCandidate(env), rejectsWith("stale-main-revision"));
  assert.equal(readFileSync(env.GITHUB_OUTPUT, "utf8"), "earlier_step=preserved\n");
});

test("invalid output configuration fails before network; write errors hide paths", async (t) => {
  const { env, directory } = publicationFixture(t);
  const requests = githubMock(t);
  await assert.rejects(prepareCandidate({ ...env, GITHUB_OUTPUT: "" }), rejectsWith("prepare-output-failed"));
  assert.equal(requests.length, 0);
  await assert.rejects(prepareCandidate({ ...env, GITHUB_OUTPUT: join(directory, "PRIVATE_PATH_SENTINEL", "output") }), error => {
    assert.doesNotMatch(preparationFailure(error), /PRIVATE_PATH_SENTINEL/);
    return rejectsWith("prepare-output-failed")(error);
  });
  assert.equal(preparationFailure(new Error("TOKEN_SENTINEL")),
    "[prepare-container-candidate] prepare-failed: Container candidate preparation failed; inspect the reviewed action implementation and runner setup.");
});

for (const [name, scenario, expectedCode] of [
  ["matching", {}, undefined], ["denied", { status: 403 }, "canonical-main-unavailable"],
  ["malformed", { body: "BODY_SENTINEL" }, "canonical-main-invalid-response"],
  ["transport", { failure: "request" }, "canonical-main-unavailable"],
  ["stale", { body: JSON.stringify(mainReference("c".repeat(40))) }, "stale-main-revision"],
]) {
  test(`generated executable ${name}: correct exit, safe stderr and successful-only output`, (t) => {
    const { env } = publicationFixture(t);
    const result = spawnSync(process.execPath, [
      "--import", fileURLToPath(new URL("./support/prepare-http-fixture.mjs", import.meta.url)),
      fileURLToPath(new URL("../actions/container-evidence/lib/prepare.mjs", import.meta.url)),
    ], { env: { ...env, PREPARE_HTTP_SCENARIO: JSON.stringify(scenario) }, encoding: "utf8", timeout: 5000 });
    assert.equal(result.error, undefined);
    assert.equal(result.status, expectedCode ? 1 : 0, result.stderr);
    assert.equal(result.stdout, "");
    assert.doesNotMatch(result.stderr, /TOKEN_SENTINEL|BODY_SENTINEL|TRANSPORT_SENTINEL|Bearer/);
    if (expectedCode) assert.match(result.stderr, new RegExp(`\\] ${expectedCode}:`));
    else assert.equal(result.stderr, "");
    assert.equal(existsSync(env.GITHUB_OUTPUT), !expectedCode);
  });
}

test("prepare metadata requires a token and maps it only into the process environment", () => {
  const action = readFileSync(new URL("../actions/prepare-container-candidate/action.yml", import.meta.url), "utf8");
  assert.match(action, /github-token:\n\s+description: [^\n]+\n\s+required: true/);
  assert.match(action, /env:\n\s+GH_TOKEN: \$\{\{ inputs.github-token \}\}/);
  assert.match(action, /run: node "\$ACTION_PATH\/\.\.\/container-evidence\/lib\/prepare\.mjs"/);
  assert.equal([...action.matchAll(/inputs\.github-token/g)].length, 1);
  assert.match(action, /outputs:\n\s+image_ref:/);
  assert.match(action, /\n  tag:\n/);
});
