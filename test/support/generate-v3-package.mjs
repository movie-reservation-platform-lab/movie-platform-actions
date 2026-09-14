/** Offline interoperability fixture: actual writer, synthetic reports/approvals, no signing. */
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { generateV3Evidence } from "../../actions/container-evidence/lib/candidate-v3.mjs";
import { baseline, policyFixture } from "./policy-fixture.mjs";

if (process.argv.length !== 3) throw new Error("Usage: node test/support/generate-v3-package.mjs <new-output-directory>");
const root = resolve(process.argv[2]);
mkdirSync(root, { mode: 0o700 });
const risk = JSON.parse(readFileSync(new URL("../fixtures/vulnerability-policy/risk-accepted.json", import.meta.url)));
for (const scenario of ["not-affected", "risk-accepted", "clean", "unused-expired"]) {
  const workspace = join(root, scenario);
  const evidence = join(workspace, "security-evidence");
  const pack = join(workspace, "package");
  mkdirSync(workspace);
  mkdirSync(evidence);
  mkdirSync(pack);
  const report = structuredClone(baseline.report);
  const records = scenario === "risk-accepted" ? [risk] : structuredClone(baseline.records);
  if (scenario === "clean" || scenario === "unused-expired") report.Results[0].Vulnerabilities = report.Results[0].Vulnerabilities.slice(1);
  if (scenario === "clean") records.length = 0;
  if (scenario === "unused-expired") records[0].expiresAt = "2026-09-02T00:00:00Z";
  const members = {
    "recommendation-mcp-provenance.json": { dsseEnvelope: { payloadType: "application/vnd.in-toto+json" } },
    "recommendation-mcp.cdx.json": { bomFormat: "CycloneDX", specVersion: "1.6", version: 1, metadata: { component: { type: "container", name: baseline.expectedImage } }, components: [] },
    "recommendation-mcp-vulnerabilities.json": report,
  };
  for (const [name, value] of Object.entries(members)) writeFileSync(join(evidence, name), JSON.stringify(value), { flag: "wx" });
  await generateV3Evidence({
    COMPONENT: baseline.component, GITHUB_REPOSITORY: "movie-reservation-platform-lab/movie-recommendation-mcp",
    GITHUB_REF: "refs/heads/main", GITHUB_EVENT_NAME: "push", GITHUB_SERVER_URL: "https://github.com", GITHUB_JOB: "publish-image",
    GITHUB_SHA: "b".repeat(40), GITHUB_RUN_ID: "123", GITHUB_RUN_ATTEMPT: "2", CANDIDATE_DIGEST: "sha256:" + "a".repeat(64),
    CANDIDATE_REPOSITORY: baseline.expectedImage.split("@")[0], ATTESTATION_ID: "456",
    ATTESTATION_URL: "https://github.com/movie-reservation-platform-lab/movie-recommendation-mcp/attestations/456",
    GITHUB_WORKSPACE: workspace, GITHUB_STEP_SUMMARY: join(workspace, "summary.md"),
  }, policyFixture(records).read, () => baseline.now);
  for (const name of [...Object.keys(members), "component-candidate-evidence-v1alpha3.json"]) copyFileSync(join(evidence, name), join(pack, name));
  console.log(pack);
}
