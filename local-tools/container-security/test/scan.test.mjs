import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:net";
import { once } from "node:events";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { scannerArguments, scannerImage, cacheVolume } from "../lib/trivy-runner.mjs";

const script = fileURLToPath(new URL("../lib/scan.mjs", import.meta.url));
async function fixture(t, scenario = "high") {
  const directory = mkdtempSync(join(tmpdir(), "local-scan-test-"));
  const socket = join(directory, "docker.sock");
  const server = createServer();
  server.listen(socket);
  await once(server, "listening");
  t.after(() => { server.close(); rmSync(directory, { recursive: true, force: true }); });
  const bin = join(directory, "bin");
  mkdirSync(bin);
  const docker = join(bin, "docker");
  copyFileSync(new URL("fixtures/docker.mjs", import.meta.url), docker);
  chmodSync(docker, 0o700);
  const env = {
    ...process.env, PATH: `${bin}:${process.env.PATH}`, DOCKER_HOST: `unix://${socket}`,
    DOCKER_CONTEXT: "", FAKE_SOCKET: socket, FAKE_SCENARIO: scenario,
    FAKE_CALLS: join(directory, "calls"),
  };
  const root = join(directory, "reports with spaces");
  const args = [script, "example:local", "--output-dir", root];
  return {
    directory, root, socket, env, args,
    run: () => spawnSync(process.execPath, args, { env, cwd: directory, encoding: "utf8", timeout: 15_000 }),
    calls: () => existsSync(env.FAKE_CALLS) ? readFileSync(env.FAKE_CALLS, "utf8").trim().split("\n").map(JSON.parse) : [],
    reports: () => existsSync(root) ? readdirSync(root).map(name => join(root, name)) : [],
  };
}

for (const [scenario, status] of [["high", 0], ["critical", 1]]) {
  test(`${scenario}: actual shared evaluator, complete retained report, local presentation`, async (t) => {
    const f = await fixture(t, scenario);
    const result = f.run();
    assert.equal(result.status, status, result.stderr);
    const [run] = f.reports();
    const report = JSON.parse(readFileSync(join(run, "vulnerabilities.json")));
    assert.equal(report.Results[0].Vulnerabilities[0].Severity, scenario.toUpperCase());
    assert.match(result.stdout, /HIGH: \d+; CRITICAL: \d+/);
    assert.match(result.stdout, /not PR authority/);
    assert.doesNotMatch(result.stdout, /Downloadable evidence|Local PR image/);
    assert.deepEqual(readdirSync(run).sort(), ["summary.txt", "vulnerabilities.json"]);
    assert.equal(f.calls().filter(args => args.includes("run")).length, 1);
  });
}

for (const scenario of ["scanner-error", "database-error", "malformed", "wrong-tag", "wrong-id", "invalid-report"]) {
  test(`${scenario}: failure is exit 2, retains diagnostics and cannot claim a policy result`, async (t) => {
    const f = await fixture(t, scenario);
    const result = f.run();
    assert.equal(result.status, 2, result.stderr);
    assert.match(result.stderr, scenario === "database-error" ? /Database failure/ : /failure|failed/i);
    assert.doesNotMatch(result.stdout + result.stderr, /PRIVATE_SENTINEL|Policy passed|Policy rejected/);
    assert.deepEqual(readdirSync(f.reports()[0]), ["report.partial.json"]);
    if (scenario.endsWith("-error")) {
      const run = f.calls().find(args => args.includes("run"));
      const cleanup = f.calls().find(args => args.includes("rm"));
      assert.equal(cleanup.at(-1), run[run.indexOf("--name") + 1]);
    }
  });
}

test("repeat scan retains old report and uses the same cache without stale-result reuse", async (t) => {
  const f = await fixture(t);
  assert.equal(f.run().status, 0);
  const first = f.reports()[0];
  const previous = readFileSync(join(first, "vulnerabilities.json"), "utf8");
  f.env.FAKE_SCENARIO = "scanner-error";
  assert.equal(f.run().status, 2);
  assert.equal(f.reports().length, 2);
  assert.equal(readFileSync(join(first, "vulnerabilities.json"), "utf8"), previous);
  for (const call of f.calls().filter(args => args.includes("run"))) {
    assert.ok(call.includes(`${cacheVolume}:/root/.cache/trivy`));
  }
});

test("failed container removal reports recovery guidance without hiding the scan failure or exposing Docker diagnostics", async (t) => {
  const f = await fixture(t, "cleanup-error");
  const result = f.run();
  assert.equal(result.status, 2, result.stderr);
  assert.match(result.stderr, /Scanner failure/);
  const scan = f.calls().find(args => args.includes("run"));
  const containerName = scan[scan.indexOf("--name") + 1];
  const cleanup = f.calls().find(args => args.includes("rm"));
  assert.deepEqual(cleanup, ["--host", `unix://${f.socket}`, "rm", "--force", containerName]);
  assert.ok(result.stderr.includes(
    `Container cleanup could not complete. When Docker is available, remove container ${containerName}.`,
  ));
  assert.doesNotMatch(result.stdout + result.stderr, /PRIVATE_SENTINEL|CLEANUP_SENTINEL|Policy passed|Policy rejected/);
  assert.deepEqual(readdirSync(f.reports()[0]), ["report.partial.json"]);
});

test("context precedence and socket selection agree for inspection and scanning", async (t) => {
  const f = await fixture(t);
  f.env.DOCKER_CONTEXT = "desktop-linux";
  f.env.DOCKER_HOST = "tcp://ignored:2375";
  assert.equal(f.run().status, 0);
  assert.deepEqual(f.calls()[0], ["context", "inspect", "desktop-linux", "--format", "{{.Endpoints.docker.Host}}"]);
  for (const call of f.calls().slice(1)) assert.equal(call[1], `unix://${f.socket}`);
  assert.ok(f.calls().find(args => args.includes("run")).includes(`${f.socket}:/var/run/docker.sock:ro`));
});

test("setup rejects unsupported transport, missing image, wrong platform, and symlink output before scanning", async (t) => {
  const f = await fixture(t);
  f.env.DOCKER_HOST = "tcp://unsupported:2375";
  assert.equal(f.run().status, 2);
  f.env.DOCKER_HOST = `unix://${f.socket}`;
  for (const scenario of ["missing-image", "wrong-platform"]) {
    f.env.FAKE_SCENARIO = scenario;
    assert.equal(f.run().status, 2);
  }
  f.env.FAKE_SCENARIO = "high";
  symlinkSync(f.directory, f.root);
  assert.equal(f.run().status, 2);
  assert.ok(f.calls().every(args => !args.includes("run")));
});

test("interrupt retains partial output and removes only the named scanner container", async (t) => {
  const f = await fixture(t, "interrupt");
  const child = spawn(process.execPath, f.args, { env: f.env, cwd: f.directory, stdio: "pipe" });
  const completed = once(child, "close");
  const deadline = Date.now() + 5000;
  while (!f.calls().some(args => args.includes("run"))) {
    assert.ok(Date.now() < deadline, "scanner should start");
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  child.kill("SIGINT");
  assert.equal((await completed)[0], 2);
  assert.deepEqual(readdirSync(f.reports()[0]), ["report.partial.json"]);
  assert.ok(f.calls().some(args => args.includes("rm")));
});

test("scanner settings match hosted policy and never request remote target lookup or skipped updates", () => {
  const hosted = readFileSync(new URL("../../../actions/container-evidence/action.yml", import.meta.url), "utf8");
  const args = scannerArguments("/test.sock", "example:local", "example-container");
  const version = /version: v(\S+)/.exec(hosted)[1];
  assert.match(scannerImage, new RegExp(`:${version.replaceAll(".", "\\.")}@sha256:[a-f0-9]{64}$`));
  for (const [flag, input] of [["--scanners", "scanners"], ["--vuln-type", "vuln-type"], ["--severity", "severity"], ["--timeout", "timeout"]]) {
    assert.ok(hosted.includes(`${input}: ${args[args.indexOf(flag) + 1]}`));
  }
  assert.ok(args.includes("--ignore-unfixed=false"));
  assert.ok(hosted.includes("ignore-unfixed: false"));
  assert.equal(args[args.indexOf("--exit-code") + 1], "0");
  assert.equal(args[args.indexOf("--format") + 1], "json");
  assert.equal(args[args.indexOf("--image-src") + 1], "docker");
  assert.ok(args.every(arg => !arg.startsWith("--skip-")));
});

for (const [scenario, policy, status] of [
  ["v3-approved", "approved", 0], ["v3-unapproved", "approved", 1],
  ["v3-no-purl", "approved", 1], ["v3-approved", "empty", 1],
  ["v3-high", "empty", 0], ["v3-approved", "failed", 2], ["v3-wrong-id", "approved", 2],
]) {
  test(`${scenario}/${policy}: real v3 CLI retains complete decisions with correct exit and no authority`, async t => {
    const f = await fixture(t, scenario);
    const baseline = JSON.parse(readFileSync(new URL("../../../test/fixtures/vulnerability-policy/baseline.json", import.meta.url)));
    const reportPath = join(f.directory, "synthetic-report.json");
    writeFileSync(reportPath, JSON.stringify(baseline.report));
    Object.assign(f.env, { FAKE_REPORT: reportPath, FAKE_POLICY_MODE: policy, GH_TOKEN: "TOKEN_SENTINEL",
      NODE_OPTIONS: `--import=${fileURLToPath(new URL("../../../test/support/mock-policy-https.mjs", import.meta.url))}`,
      TRIVY_IGNORE_UNFIXED: "true", TRIVY_IGNOREFILE: "/evil/ignore" });
    f.args.push("--evidence-version", "v1alpha3", "--component", "recommendation-mcp");
    const result = f.run();
    assert.equal(result.status, status, result.stderr);
    assert.doesNotMatch(result.stdout + result.stderr, /TOKEN_SENTINEL|PRIVATE_SENTINEL/);
    const run = f.reports()[0];
    assert.ok(!readdirSync(run).some(name => name.includes("candidate-evidence")));
    if (status === 2) {
      assert.ok(!existsSync(join(run, "summary.txt")));
      assert.ok(!existsSync(join(run, "vulnerability-policy.json")));
      assert.ok(existsSync(join(run, "report.partial.json")));
    } else {
      const report = JSON.parse(readFileSync(join(run, "vulnerabilities.json")));
      const diagnostic = JSON.parse(readFileSync(join(run, "vulnerability-policy.json")));
      assert.equal(diagnostic.diagnosticOnly, true);
      assert.equal(diagnostic.evaluation.findings.length, report.Results[0].Vulnerabilities.length);
      assert.equal(diagnostic.evaluation.blockingCritical === 0, status === 0);
      assert.match(result.stdout, /not PR authority/);
      if (scenario === "v3-approved" && policy === "approved") {
        assert.equal(diagnostic.evaluation.result, "passed-with-exemptions");
        assert.equal(diagnostic.evaluation.counts.critical, 1);
        assert.match(result.stdout, /passed-with-exemptions/);
      }
    }
    const args = f.calls().find(args => args.includes("run"));
    assert.ok(args && !args.includes("--env"), "host environment and token are never forwarded into local Trivy");
    assert.equal(args[args.indexOf("--ignorefile") + 1], "/dev/null");
  });
}

test("v3 selection rejects missing credentials/component, unknown versions and caller policy paths before scanning", async t => {
  const f = await fixture(t);
  for (const extra of [
    ["--evidence-version", "v1alpha3"],
    ["--evidence-version", "v1alpha3", "--component", "recommendation-mcp"],
    ["--evidence-version", "v1alpha99"],
    ["--policy-file", "/tmp/unreviewed.json"],
  ]) {
    const result = spawnSync(process.execPath, [...f.args, ...extra], { env: { ...f.env, GH_TOKEN: "" }, encoding: "utf8" });
    assert.equal(result.status, 2);
  }
  assert.equal(f.calls().length, 0);
});
