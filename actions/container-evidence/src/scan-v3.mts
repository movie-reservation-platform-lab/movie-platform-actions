/** Scan exact GHCR subjects in the existing pinned Trivy container, outside producer config. */
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { publicationContext, requireDigest } from "./profile.mjs";
import { requireRuntime, RuntimeError, safeFailure } from "./runtime-files.mjs";
import { pathToFileURL } from "node:url";

export const hostedScannerImage = "docker.io/aquasec/trivy:0.70.0@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e";
type DockerRun = (args: string[], env: NodeJS.ProcessEnv, timeout: number, limit: number) => Buffer;

export function hostedScannerArguments(image: string, format: "json" | "cyclonedx", name: string, registryConfig: string): string[] {
  requireRuntime(!/[:,\r\n\0]/.test(registryConfig), "Registry configuration path contains unsupported mount separators.");
  return ["--host", "unix:///var/run/docker.sock", "run", "--rm", "--name", name,
    "--volume", `${registryConfig}:/registry-auth:ro`, "--env", "DOCKER_CONFIG=/registry-auth", hostedScannerImage,
    "image", "--image-src", "remote", "--platform", "linux/amd64",
    "--config", "/dev/null", "--ignorefile", "/dev/null", "--ignore-unfixed=false",
    "--scanners", "vuln", "--vuln-type", "os,library", "--format", format,
    "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", "--list-all-pkgs",
    "--quiet", "--exit-code", "0", "--timeout", "5m", image];
}

function docker(args: string[], env: NodeJS.ProcessEnv, timeout: number, limit: number): Buffer {
  return execFileSync("docker", args, { env, cwd: env.DOCKER_CONFIG!, timeout, killSignal: "SIGKILL", maxBuffer: limit, stdio: ["ignore", "pipe", "pipe"] });
}

/** Only a fresh GHCR-scoped auth directory is mounted; never producer config or its workspace/socket. */
export function scanHosted(env: NodeJS.ProcessEnv, run: DockerRun = docker): void {
  const profile = publicationContext(env);
  const digest = requireDigest(env.CANDIDATE_DIGEST)!;
  requireRuntime(env.RUNNER_TEMP && env.GITHUB_WORKSPACE && env.GH_TOKEN && env.GITHUB_ACTOR, "Hosted scan requires runner paths and registry credentials.");
  requireRuntime(/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:\[bot\])?$/.test(env.GITHUB_ACTOR), "Invalid registry actor.");
  const workspace = realpathSync(env.GITHUB_WORKSPACE);
  const config = mkdtempSync(join(realpathSync(env.RUNNER_TEMP), "v3-scanner-"));
  const scannerEnv: NodeJS.ProcessEnv = { PATH: env.PATH, DOCKER_CONFIG: config };
  try {
    // Host-scoped Docker credentials avoid sending a global Trivy password to DB mirrors.
    writeFileSync(join(config, "config.json"), JSON.stringify({ auths: { "ghcr.io": {
      auth: Buffer.from(`${env.GITHUB_ACTOR}:${env.GH_TOKEN}`).toString("base64"),
    } } }), { flag: "wx", mode: 0o600 });
    for (const [format, filename] of [["cyclonedx", profile.sbom], ["json", profile.vulnerabilities]] as const) {
      const name = `movie-platform-v3-scan-${randomUUID()}`;
      const path = join(workspace, "security-evidence", filename);
      try {
        const bytes = run(hostedScannerArguments(`${profile.image}@${digest}`, format, name, config), scannerEnv, 360_000, 16 * 1024 * 1024);
        requireRuntime(bytes.length > 0 && bytes.length <= 16 * 1024 * 1024, "Hosted scan report must be nonempty and within limit=16777216 bytes; reproduce using the local scanning path.");
        writeFileSync(path, bytes, { flag: "wx", mode: 0o600 });
      } catch (error) {
        try { run(["--host", "unix:///var/run/docker.sock", "rm", "--force", name], scannerEnv, 10_000, 64 * 1024); } catch { /* bounded cleanup only */ }
        if (error instanceof RuntimeError) throw error;
        throw new RuntimeError("Hosted Trivy scan failed or exceeded its six-minute/16 MiB output limit. Reproduce with the local scanning helper; incomplete output is not a policy result.");
      }
    }
  } finally { rmSync(config, { recursive: true, force: true }); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { scanHosted(process.env); }
  catch (error) { console.error(safeFailure(error)); process.exitCode = 1; }
}
