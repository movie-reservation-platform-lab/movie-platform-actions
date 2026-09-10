/** Local diagnostics only. Builds and hosted publication remain outside this tool. */
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { cacheVolume, scan, scannerImage } from "./scanner.mjs";

const usage = "Usage: node scan.mjs <local-image:tag> [--output-dir <directory>]";
const localImagePattern = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;
const evaluator = fileURLToPath(new URL("../../../actions/container-evidence/lib/evaluate-vulnerabilities.mjs", import.meta.url));

function command(args: string[], env: NodeJS.ProcessEnv): string {
  const result = spawnSync("docker", args, {
    env, encoding: "utf8", timeout: 30_000, killSignal: "SIGKILL", maxBuffer: 64 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error || result.status !== 0) throw new Error("Docker setup failed. Check the active context, daemon access, and that the local image exists.");
  return result.stdout.trim();
}

/** DOCKER_CONTEXT overrides DOCKER_HOST, matching Docker CLI selection. */
function dockerConnection(): { endpoint: string; socket: string; env: NodeJS.ProcessEnv } {
  const context = process.env.DOCKER_CONTEXT;
  const endpoint = context
    ? command(["context", "inspect", context, "--format", "{{.Endpoints.docker.Host}}"], process.env)
    : process.env.DOCKER_HOST || command(["context", "inspect", "--format", "{{.Endpoints.docker.Host}}"], process.env);
  if (!endpoint.startsWith("unix:///")) throw new Error("Docker setup requires a local Unix socket; SSH, TCP and Windows named pipes are unsupported.");
  const socket = endpoint.slice("unix://".length);
  if (/[:,\r\n\0]/.test(socket) || !statSync(socket).isSocket()) throw new Error("Docker endpoint must identify an existing Unix socket with no mount separators.");
  const env = { ...process.env };
  for (const key of ["DOCKER_CONTEXT", "DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"]) delete env[key];
  return { endpoint, socket, env };
}

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function imageId(endpoint: string, image: string, env: NodeJS.ProcessEnv): string {
  const inspected = command(["--host", endpoint, "image", "inspect", "--format", "{{.Id}} {{.Os}}/{{.Architecture}}", image], env);
  const match = /^(sha256:[a-f0-9]{64}) (\S+)$/.exec(inspected);
  if (!match) throw new Error("Docker returned invalid local image metadata.");
  if (match[2] !== "linux/amd64") throw new Error("Image must be linux/amd64. Rebuild the producer production target with docker build --platform linux/amd64.");
  return match[1]!;
}

/** The shared evaluator owns all finding validation and the CRITICAL policy. */
function evaluate(directory: string, image: string): { high: string; critical: string; status: number } {
  const output = join(directory, ".evaluator-output");
  const summary = join(directory, ".evaluator-summary");
  try {
    for (const path of [output, summary]) writeFileSync(path, "", { flag: "wx", mode: 0o600 });
    const result = spawnSync(process.execPath, [evaluator], {
      env: {
        ...process.env, REPORT_PATH: "report.partial.json", EXPECTED_IMAGE: image,
        SUBJECT_KIND: "local", EVIDENCE_ARTIFACT_NAME: "local-diagnostics",
        GITHUB_WORKSPACE: directory, GITHUB_OUTPUT: output, GITHUB_STEP_SUMMARY: summary,
      },
      stdio: ["ignore", "pipe", "pipe"], timeout: 30_000, killSignal: "SIGKILL", maxBuffer: 64 * 1024,
    });
    const counts = /^high-count=(\d+)\ncritical-count=(\d+)\npolicy-result=(passed|failed)\n$/.exec(readFileSync(output, "utf8"));
    if (result.error || !counts || !statSync(summary).isFile() || statSync(summary).size === 0) {
      throw new Error("Report/evaluator failure. The shared evaluator could not validate the report; inspect the retained JSON.");
    }
    const expectedStatus = counts[3] === "passed" ? 0 : 1;
    if (result.status !== expectedStatus || (counts[2] === "0") !== (expectedStatus === 0)) {
      throw new Error("Report/evaluator failure: inconsistent policy result.");
    }
    return { high: counts[1]!, critical: counts[2]!, status: expectedStatus };
  } finally {
    // Private temporary output only; never retain hosted artifact/PR summary wording.
    for (const path of [output, summary]) rmSync(path, { force: true });
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === "--help") { console.log(usage); return; }
  if (!(args.length === 1 || (args.length === 3 && args[1] === "--output-dir" && args[2]))) throw new Error(usage);
  const image = args[0]!;
  if (!localImagePattern.test(image) || image.length > 255) throw new Error("Use an explicit local image:tag, not a digest, URL, or registry port.");
  if (Number(process.versions.node.split(".")[0]) !== 24) throw new Error("Use Node 24 to run this helper.");
  const { endpoint, socket, env } = dockerConnection();
  const expectedId = imageId(endpoint, image, env);
  const root = resolve(args[2] ?? ".local-container-security");
  mkdirSync(root, { recursive: true, mode: 0o700 });
  if (!lstatSync(root).isDirectory()) throw new Error("Output root must be a directory, not a symlink.");
  const directory = mkdtempSync(join(realpathSync(root), "run-"));
  console.log(`Local diagnostic scan: ${image}\nReports: ${directory}\nCache: ${cacheVolume}`);
  try {
    const scanned = await scan(endpoint, socket, image, `movie-platform-local-scan-${randomUUID()}`, env);
    const partial = join(directory, "report.partial.json");
    writeFileSync(partial, scanned.report, { flag: "wx", mode: 0o600 });
    if (scanned.failure) throw new Error(scanned.failure);
    let report: unknown;
    try { report = JSON.parse(scanned.report.toString("utf8")); }
    catch { throw new Error("Report failure: scanner output is not complete JSON."); }
    if (!object(report) || !object(report.Metadata) || report.Metadata.ImageID !== expectedId) {
      throw new Error("Report failure: scanned image ID differs from the inspected local image. Rebuild or stop retagging it, then retry.");
    }
    const outcome = evaluate(directory, image);
    const reportPath = join(directory, "vulnerabilities.json");
    renameSync(partial, reportPath);
    const summary = [
      "Local vulnerability diagnostics only", `Image: ${image}`, `Image ID: ${expectedId}`,
      `Scanner: ${scannerImage}`, `Scanned at: ${new Date().toISOString()}`,
      `HIGH: ${outcome.high}; CRITICAL: ${outcome.critical}`,
      outcome.status === 0 ? "Policy passed: no CRITICAL findings." : "Policy rejected: CRITICAL findings detected.",
      `Complete report: ${reportPath}`,
      "HIGH findings remain non-blocking locally. This is not PR authority, signed evidence, publication acceptance, or environment admission.", "",
    ].join("\n");
    writeFileSync(join(directory, "summary.txt"), summary, { flag: "wx", mode: 0o600 });
    console.log(summary);
    process.exitCode = outcome.status;
  } catch (error) {
    console.error(`Run did not complete. Inspect retained files in ${directory}; report.partial.json is not a policy result.`);
    throw error;
  }
}

try { await main(); }
catch (error) {
  // Filesystem errors can contain local paths; print only our controlled messages.
  const message = error instanceof Error && !("code" in error) ? error.message : "Local setup/report I/O failed. Check paths, permissions, and free disk space.";
  console.error(message);
  process.exitCode = 2;
}
