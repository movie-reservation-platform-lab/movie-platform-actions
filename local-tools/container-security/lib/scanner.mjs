import { spawn, spawnSync } from "node:child_process";
export const scannerImage = "docker.io/aquasec/trivy:0.70.0@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e";
export const cacheVolume = "movie-platform-local-trivy-0-70-0";
const reportLimit = 64 * 1024 * 1024;
const diagnosticLimit = 64 * 1024;
/** These settings match the hosted report step; image lookup is local Docker only. */
export function scannerArguments(socket, image, name) {
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
/** Bound output and wall time, handle interruption, and clean up only our container. */
export async function scan(endpoint, socket, image, name, env) {
    const result = await new Promise((resolve) => {
        const child = spawn("docker", ["--host", endpoint, ...scannerArguments(socket, image, name)], {
            env, stdio: ["ignore", "pipe", "pipe"],
        });
        const chunks = [];
        let size = 0;
        let diagnostics = Buffer.alloc(0);
        let failure;
        const stop = (message) => {
            failure ??= message;
            child.kill("SIGKILL");
        };
        const interrupt = () => stop("Scanner interrupted; rerun when ready.");
        process.on("SIGINT", interrupt);
        process.on("SIGTERM", interrupt);
        const timeout = setTimeout(() => stop("Scanner exceeded the six-minute total limit (including image pull)."), 360_000);
        child.stdout.on("data", (chunk) => {
            const retained = chunk.subarray(0, Math.max(0, reportLimit - size));
            if (retained.length > 0)
                chunks.push(retained);
            size += retained.length;
            if (retained.length !== chunk.length)
                stop("Scanner report exceeded the 64 MiB limit.");
        });
        child.stderr.on("data", (chunk) => {
            diagnostics = Buffer.concat([diagnostics, chunk]).subarray(-diagnosticLimit);
        });
        child.on("error", () => { failure = "Cannot start Docker. Check installation and daemon access."; });
        child.on("close", (code) => {
            clearTimeout(timeout);
            process.off("SIGINT", interrupt);
            process.off("SIGTERM", interrupt);
            if (code !== 0 && !failure) {
                // Classify only; never expose raw process errors, URLs, or credentials.
                failure = /database|vulnerability DB|java DB|db error|db update/i.test(diagnostics.toString("utf8"))
                    ? "Database failure. Check network access or reset the dedicated cache and retry."
                    : "Scanner failure. Check Docker, network access, disk space, and cache contention; then retry.";
            }
            resolve({ report: Buffer.concat(chunks, size), failure });
        });
    });
    if (result.failure) {
        const cleanup = spawnSync("docker", ["--host", endpoint, "rm", "--force", name], {
            env, stdio: "ignore", timeout: 10_000, killSignal: "SIGKILL",
        });
        if (cleanup.error) {
            console.error(`Container cleanup could not complete. When Docker is available, remove container ${name}.`);
        }
    }
    return result;
}
