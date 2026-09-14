/**
 * Command-line entry point for checking a locally built production image.
 * Validates Docker/image setup, asks the Trivy runner for a report, applies the
 * shared CRITICAL policy, and saves diagnostics with a readable local summary.
 * The command does not build images or publish hosted evidence.
 */
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { cacheVolume, runTrivy, scannerImage } from "./trivy-runner.mjs";

const usage = "Usage: node scan.mjs <local-image:tag> [--output-dir <directory>] [--evidence-version v1alpha2|v1alpha3 --component <component>]";
const localImagePattern =
  /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;
const evaluator = fileURLToPath(
  new URL("../../../actions/container-evidence/lib/evaluate-vulnerabilities.mjs", import.meta.url),
);

type DockerConnection = {
  endpoint: string;
  socket: string;
  env: NodeJS.ProcessEnv;
};

type PolicyOutcome = {
  high: string;
  critical: string;
  status: number;
  details?: string;
};

type ScanOptions = { version: "v1alpha2" | "v1alpha3"; component: string | undefined; output: string };

/** Keep old invocations strict; v3 selects a component, never a caller policy file. */
function parseOptions(args: string[]): ScanOptions {
  const options = new Map<string, string>();
  for (let index = 1; index < args.length; index += 2) {
    const key = args[index]!;
    const value = args[index + 1];
    if (!["--output-dir", "--evidence-version", "--component"].includes(key) || !value || value.startsWith("--") || options.has(key)) throw new Error(usage);
    options.set(key, value);
  }
  const version = options.get("--evidence-version") ?? "v1alpha2";
  const component = options.get("--component");
  if (version !== "v1alpha2" && version !== "v1alpha3") throw new Error(usage);
  if (version === "v1alpha3" && !["reservation-agent", "recommendation-service", "reservation-mcp", "recommendation-mcp", "reservation-web"].includes(component ?? "")) throw new Error("V3 requires an allowlisted --component; see --help.");
  if (version === "v1alpha2" && component !== undefined) throw new Error("--component requires --evidence-version v1alpha3.");
  if (version === "v1alpha3" && !process.env.GH_TOKEN) throw new Error("V3 requires GH_TOKEN with read access to the central actions approvals. No policy fallback is allowed.");
  return { version, component, output: options.get("--output-dir") ?? ".local-container-security" };
}

/** Runs a bounded Docker setup command and hides raw process errors from local output. */
function runDockerCommand(args: string[], env: NodeJS.ProcessEnv): string {
  const result = spawnSync("docker", args, {
    env,
    encoding: "utf8",
    timeout: 30_000,
    killSignal: "SIGKILL",
    maxBuffer: 64 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error || result.status !== 0) {
    throw new Error(
      "Docker setup failed. Check the active context, daemon access, and that the local image exists.",
    );
  }
  return result.stdout.trim();
}

/** Selects a local Unix socket, honoring DOCKER_CONTEXT before DOCKER_HOST. */
function resolveDockerConnection(): DockerConnection {
  const context = process.env.DOCKER_CONTEXT;
  const endpoint = context
    ? runDockerCommand(
        ["context", "inspect", context, "--format", "{{.Endpoints.docker.Host}}"],
        process.env,
      )
    : process.env.DOCKER_HOST || runDockerCommand(
        ["context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
        process.env,
      );
  if (!endpoint.startsWith("unix:///")) {
    throw new Error(
      "Docker setup requires a local Unix socket; SSH, TCP and Windows named pipes are unsupported.",
    );
  }
  const socket = endpoint.slice("unix://".length);
  if (/[:,\r\n\0]/.test(socket) || !statSync(socket).isSocket()) {
    throw new Error(
      "Docker endpoint must identify an existing Unix socket with no mount separators.",
    );
  }
  const env = { ...process.env };
  for (const key of ["DOCKER_CONTEXT", "DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"]) {
    delete env[key];
  }
  return { endpoint, socket, env };
}

/** Narrows untrusted JSON to a non-null object with named fields. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Returns the local image ID after checking that Docker reports a linux/amd64 image. */
function inspectImageId(endpoint: string, image: string, env: NodeJS.ProcessEnv): string {
  const inspected = runDockerCommand(
    ["--host", endpoint, "image", "inspect", "--format", "{{.Id}} {{.Os}}/{{.Architecture}}", image],
    env,
  );
  const match = /^(sha256:[a-f0-9]{64}) (\S+)$/.exec(inspected);
  if (!match) {
    throw new Error("Docker returned invalid local image metadata.");
  }
  if (match[2] !== "linux/amd64") {
    throw new Error(
      "Image must be linux/amd64. Rebuild the producer production target with docker build --platform linux/amd64.",
    );
  }
  return match[1]!;
}

/** Applies the shared evaluator and verifies its result; removes temporary GitHub output files. */
function evaluateReport(directory: string, image: string, options: ScanOptions): PolicyOutcome {
  const output = join(directory, ".evaluator-output");
  const summary = join(directory, ".evaluator-summary");
  try {
    for (const path of [output, summary]) {
      writeFileSync(path, "", { flag: "wx", mode: 0o600 });
    }
    const result = spawnSync(process.execPath, [evaluator], {
      env: {
        ...process.env,
        REPORT_PATH: "report.partial.json",
        EXPECTED_IMAGE: image,
        SUBJECT_KIND: "local",
        EVIDENCE_VERSION: options.version,
        COMPONENT: options.component,
        EVIDENCE_ARTIFACT_NAME: "local-diagnostics",
        GITHUB_WORKSPACE: directory,
        GITHUB_OUTPUT: output,
        GITHUB_STEP_SUMMARY: summary,
      },
      stdio: ["ignore", "pipe", "pipe"],
      timeout: options.version === "v1alpha3" ? 150_000 : 30_000,
      killSignal: "SIGKILL",
      maxBuffer: 64 * 1024,
    });
    const counts = /^high-count=(\d+)\ncritical-count=(\d+)\npolicy-result=(passed|passed-with-exemptions|failed)\n$/.exec(
      readFileSync(output, "utf8"),
    );
    if (result.error || !counts || !statSync(summary).isFile() || statSync(summary).size === 0) {
      throw new Error(
        options.version === "v1alpha3"
          ? "V3 report/policy evaluation failure. Inspect retained vulnerability-policy-error.txt when present and report.partial.json; no policy fallback was used."
          : "Report/evaluator failure. The shared evaluator could not validate the report; inspect the retained JSON.",
      );
    }
    const expectedStatus = counts[3] === "failed" ? 1 : 0;
    if (result.status !== expectedStatus) {
      throw new Error("Report/evaluator failure: inconsistent policy result.");
    }
    if (options.version === "v1alpha3") {
      const diagnosticPath = join(directory, "vulnerability-policy.json");
      if (!lstatSync(diagnosticPath).isFile() || statSync(diagnosticPath).size > 1024 * 1024) throw new Error("Invalid local policy diagnostic file.");
      const diagnostic: unknown = JSON.parse(readFileSync(diagnosticPath, "utf8"));
      const e = isRecord(diagnostic) ? diagnostic.evaluation : undefined;
      if (!isRecord(diagnostic) || diagnostic.diagnosticOnly !== true || !isRecord(e) || !isRecord(e.counts) || !isRecord(e.exempted) ||
        e.subject !== image || e.result !== counts[3] || e.counts.high !== Number(counts[1]) || e.counts.critical !== Number(counts[2]) ||
        ![e.blockingCritical, e.exempted.notAffected, e.exempted.riskAccepted].every((value) => typeof value === "number" && Number.isSafeInteger(value) && value >= 0) ||
        Number(e.blockingCritical) + Number(e.exempted.notAffected) + Number(e.exempted.riskAccepted) !== e.counts.critical ||
        (e.blockingCritical === 0) !== (expectedStatus === 0) ||
        (e.result === "passed") !== (e.counts.critical === 0)) throw new Error("Report/evaluator failure: inconsistent approved policy result.");
      if (statSync(summary).size > 256 * 1024) throw new Error("Local policy summary exceeds its 256 KiB limit.");
      return { high: counts[1]!, critical: counts[2]!, status: expectedStatus, details: readFileSync(summary, "utf8") };
    }
    if (counts[3] === "passed-with-exemptions" || (counts[2] === "0") !== (expectedStatus === 0)) throw new Error("Report/evaluator failure: inconsistent strict policy result.");
    return { high: counts[1]!, critical: counts[2]!, status: expectedStatus };
  } finally {
    // Private temporary output only; never retain hosted artifact/PR summary wording.
    for (const path of [output, summary]) {
      rmSync(path, { force: true });
    }
  }
}

/** Parses scanner output and confirms it describes the image inspected before scanning. */
function validateReportImage(reportBytes: Buffer, expectedId: string): void {
  let report: unknown;
  try {
    report = JSON.parse(reportBytes.toString("utf8"));
  } catch {
    throw new Error("Report failure: scanner output is not complete JSON.");
  }
  if (!isRecord(report) || !isRecord(report.Metadata) || report.Metadata.ImageID !== expectedId) {
    throw new Error(
      "Report failure: scanned image ID differs from the inspected local image. Rebuild or stop retagging it, then retry.",
    );
  }
}

/** Formats the evaluated counts and report location without implying hosted evidence authority. */
function renderSummary(
  image: string,
  expectedId: string,
  outcome: PolicyOutcome,
  reportPath: string,
): string {
  return [
    "Local vulnerability diagnostics only",
    `Image: ${image}`,
    `Image ID: ${expectedId}`,
    `Scanner: ${scannerImage}`,
    `Scanned at: ${new Date().toISOString()}`,
    `HIGH: ${outcome.high}; CRITICAL: ${outcome.critical}`,
    outcome.details ?? (outcome.status === 0
      ? "Policy passed: no CRITICAL findings."
      : "Policy rejected: CRITICAL findings detected."),
    `Complete report: ${reportPath}`,
    "HIGH findings remain non-blocking locally. This is not PR authority, signed evidence, publication acceptance, or environment admission.",
    "",
  ].join("\n");
}

/** Handles CLI input, scans into a fresh run directory, and records the policy outcome. */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === "--help") {
    console.log(usage);
    return;
  }
  if (args.length === 0) {
    throw new Error(usage);
  }
  const options = parseOptions(args);
  const image = args[0]!;
  if (!localImagePattern.test(image) || image.length > 255) {
    throw new Error("Use an explicit local image:tag, not a digest, URL, or registry port.");
  }
  if (Number(process.versions.node.split(".")[0]) !== 24) {
    throw new Error("Use Node 24 to run this helper.");
  }
  const { endpoint, socket, env } = resolveDockerConnection();
  const expectedId = inspectImageId(endpoint, image, env);
  const root = resolve(options.output);
  mkdirSync(root, { recursive: true, mode: 0o700 });
  if (!lstatSync(root).isDirectory()) {
    throw new Error("Output root must be a directory, not a symlink.");
  }
  const directory = mkdtempSync(join(realpathSync(root), "run-"));
  console.log(`Local diagnostic scan: ${image}\nReports: ${directory}\nCache: ${cacheVolume}`);
  try {
    const scanned = await runTrivy(
      endpoint, socket, image, `movie-platform-local-scan-${randomUUID()}`, env,
    );
    const partial = join(directory, "report.partial.json");
    writeFileSync(partial, scanned.report, { flag: "wx", mode: 0o600 });
    if (scanned.failure) {
      throw new Error(scanned.failure);
    }
    validateReportImage(scanned.report, expectedId);
    const outcome = evaluateReport(directory, image, options);
    const reportPath = join(directory, "vulnerabilities.json");
    renameSync(partial, reportPath);
    const summary = renderSummary(image, expectedId, outcome, reportPath);
    writeFileSync(join(directory, "summary.txt"), summary, { flag: "wx", mode: 0o600 });
    console.log(summary);
    process.exitCode = outcome.status;
  } catch (error) {
    console.error(
      `Run did not complete. Inspect retained files in ${directory}; report.partial.json is not a policy result.`,
    );
    throw error;
  }
}

try {
  await main();
} catch (error) {
  // Filesystem errors can contain local paths; print only our controlled messages.
  const message = error instanceof Error && !("code" in error)
    ? error.message
    : "Local setup/report I/O failed. Check paths, permissions, and free disk space.";
  console.error(message);
  process.exitCode = 2;
}
