/**
 * Runs the pinned Trivy container against an existing local Docker image.
 * Collects its JSON report within time/size limits, translates process failures
 * into safe messages, and attempts container cleanup after a failed scan.
 * Report validation and the vulnerability policy belong to the CLI/evaluator.
 */
import { spawn, spawnSync } from "node:child_process";
import type { ChildProcessByStdio } from "node:child_process";
import type { Readable } from "node:stream";

export const scannerImage =
  "docker.io/aquasec/trivy:0.70.0@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e";
export const cacheVolume = "movie-platform-local-trivy-0-70-0";
const reportLimit = 64 * 1024 * 1024;
const diagnosticLimit = 64 * 1024;

type ScanResult = {
  report: Buffer;
  failure: string | undefined;
};

type ScannerProcess = ChildProcessByStdio<null, Readable, Readable>;

/** Builds the Docker/Trivy arguments with hosted scan settings and local-only image lookup. */
export function scannerArguments(
  socket: string,
  image: string,
  name: string,
): string[] {
  return [
    "run", "--rm", "--name", name,
    "--volume", `${socket}:/var/run/docker.sock:ro`,
    "--volume", `${cacheVolume}:/root/.cache/trivy`,
    scannerImage, "image", "--image-src", "docker", "--platform", "linux/amd64",
    "--scanners", "vuln", "--vuln-type", "os,library", "--format", "json",
    "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", "--ignore-unfixed=false",
    "--quiet", "--exit-code", "0", "--timeout", "5m", image,
  ];
}

/** Starts Trivy, collects its report, and attempts cleanup if scanning fails. */
export async function runTrivy(
  endpoint: string,
  socket: string,
  image: string,
  name: string,
  env: NodeJS.ProcessEnv,
): Promise<ScanResult> {
  const child = spawn(
    "docker",
    ["--host", endpoint, ...scannerArguments(socket, image, name)],
    { env, stdio: ["ignore", "pipe", "pipe"] },
  );
  const result = await collectOutput(child);
  if (result.failure) {
    removeScannerContainer(endpoint, name, env);
  }
  return result;
}

/** Collects bounded stdout/stderr until Docker closes, retaining partial reports on failure. */
function collectOutput(child: ScannerProcess): Promise<ScanResult> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let diagnostics: Buffer = Buffer.alloc(0);
    let failure: string | undefined;

    /** Stops Docker while preserving the first timeout, size, or interruption reason. */
    const stop = (message: string) => {
      failure ??= message;
      child.kill("SIGKILL");
    };
    const clearCancellation = registerCancellation(stop);

    /** Keeps only report bytes within the limit and stops an oversized scan. */
    const collectReportChunk = (chunk: Buffer) => {
      const retained = chunk.subarray(0, Math.max(0, reportLimit - size));
      if (retained.length > 0) {
        chunks.push(retained);
      }
      size += retained.length;
      if (retained.length !== chunk.length) {
        stop("Scanner report exceeded the 64 MiB limit.");
      }
    };

    child.stdout.on("data", collectReportChunk);
    child.stderr.on("data", (chunk: Buffer) => {
      diagnostics = Buffer.concat([diagnostics, chunk]).subarray(-diagnosticLimit);
    });
    child.on("error", () => {
      failure = "Cannot start Docker. Check installation and daemon access.";
    });
    child.on("close", (code) => {
      clearCancellation();
      if (code !== 0 && !failure) {
        failure = classifyFailure(diagnostics);
      }
      resolve({ report: Buffer.concat(chunks, size), failure });
    });
  });
}

/** Routes Ctrl+C, termination, and the total time limit to stop; returns listener/timer cleanup. */
function registerCancellation(stop: (message: string) => void): () => void {
  const interrupt = () => stop("Scanner interrupted; rerun when ready.");
  process.on("SIGINT", interrupt);
  process.on("SIGTERM", interrupt);
  const timeout = setTimeout(
    () => stop("Scanner exceeded the six-minute total limit (including image pull)."),
    360_000,
  );
  return () => {
    clearTimeout(timeout);
    process.off("SIGINT", interrupt);
    process.off("SIGTERM", interrupt);
  };
}

/** Distinguishes recognizable database errors without exposing raw stderr or credentials. */
function classifyFailure(diagnostics: Buffer): string {
  return /database|vulnerability DB|java DB|db error|db update/i.test(
    diagnostics.toString("utf8"),
  )
    ? "Database failure. Check network access or reset the dedicated cache and retry."
    : "Scanner failure. Check Docker, network access, disk space, and cache contention; then retry.";
}

/** Attempts bounded removal of this run's container after Docker exits unsuccessfully. */
function removeScannerContainer(
  endpoint: string,
  name: string,
  env: NodeJS.ProcessEnv,
): void {
  const cleanup = spawnSync(
    "docker",
    ["--host", endpoint, "rm", "--force", name],
    { env, stdio: "ignore", timeout: 10_000, killSignal: "SIGKILL" },
  );
  if (cleanup.error) {
    console.error(
      `Container cleanup could not complete. When Docker is available, remove container ${name}.`,
    );
  }
}
