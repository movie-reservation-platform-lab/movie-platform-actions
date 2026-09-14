#!/usr/bin/env node
// Offline Docker double. No daemon connections, images, registry, or scanner.
import { appendFileSync, readFileSync } from "node:fs";
const args = process.argv.slice(2);
appendFileSync(process.env.FAKE_CALLS, JSON.stringify(args) + "\n");
if (args[0] === "--host") args.splice(0, 2);
const scenario = process.env.FAKE_SCENARIO;
const id = `sha256:${"a".repeat(64)}`;
if (args[0] === "context") {
  console.log(`unix://${process.env.FAKE_SOCKET}`);
} else if (args[0] === "image") {
  if (scenario === "missing-image") process.exit(1);
  console.log(`${id} linux/${scenario === "wrong-platform" ? "arm64" : "amd64"}`);
} else if (args[0] === "run") {
  if (scenario === "scanner-error" || scenario === "database-error") {
    process.stdout.write('{"incomplete":');
    console.error(scenario === "database-error" ? "failed to download vulnerability DB: PRIVATE_SENTINEL" : "PRIVATE_SENTINEL");
    process.exit(1);
  }
  if (scenario === "malformed") { console.log("not JSON"); process.exit(0); }
  if (scenario.startsWith("v3-")) {
    const report = JSON.parse(readFileSync(process.env.FAKE_REPORT));
    report.ArtifactName = args.at(-1);
    report.Metadata.ImageID = scenario === "v3-wrong-id" ? `sha256:${"b".repeat(64)}` : id;
    if (scenario === "v3-unapproved") report.Results[0].Vulnerabilities.push({ ...report.Results[0].Vulnerabilities[0], VulnerabilityID: "CVE-2099-99999" });
    if (scenario === "v3-no-purl") delete report.Results[0].Vulnerabilities[0].PkgIdentifier;
    if (scenario === "v3-high") report.Results[0].Vulnerabilities[0].Severity = "HIGH";
    console.log(JSON.stringify(report));
    process.exit(0);
  }
  if (scenario === "interrupt") {
    process.stdout.write('{"incomplete":');
    setTimeout(() => {}, 30_000);
  } else {
    console.log(JSON.stringify({
      SchemaVersion: 2, ArtifactType: "container_image",
      ArtifactName: scenario === "wrong-tag" ? "different:local" : args.at(-1),
      Metadata: { ImageID: scenario === "wrong-id" ? `sha256:${"b".repeat(64)}` : id },
      Results: [{ Vulnerabilities: [{
        VulnerabilityID: "CVE-EXAMPLE", PkgName: "example", InstalledVersion: "1.0",
        Severity: scenario === "critical" ? "CRITICAL" : scenario === "invalid-report" ? "surprise" : "HIGH",
      }] }],
    }));
  }
} else if (args[0] !== "rm") {
  console.error("Unexpected fake Docker command");
  process.exit(1);
}
