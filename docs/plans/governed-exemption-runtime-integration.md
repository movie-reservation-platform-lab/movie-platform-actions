# Implementation Plan: Governed Exemption Runtime Integration

## 1. Summary

Prepare the next bounded actions #5 runtime PR after environments slices E/F.
Connect hosted evidence generation and local diagnostics to the existing pure
evaluator and reviewed v1alpha3 contract. This document is the initial inspection
checkpoint requested by the user and the subsequent authorized implementation.
The user confirmed latest approvals and accepted recommendation MCP as the first
adopter, with consumer migration and real exemption requests kept separate.

Proposed PR title: `[ai] #5 Integrate governed vulnerability policy into container scanning`.
Use `[ai]` prefixes for implementation commits as well.

### Implementation and verification record

- Added fixed-authority bounded Node HTTPS acquisition, immutable Git blob checks,
  strict JSON and regular-file adapters, and shared approved evaluation/presentation.
- Added explicit hosted/local v3 dispatch; legacy defaults remain strict. Hosted v3
  scanning uses the existing pinned Trivy container with isolated configuration and
  temporary GHCR-scoped authentication. Local scanning receives no GitHub credential.
- The v3 writer acquires/evaluates once, binds the original report, rechecks retained
  file bytes and emits only when no CRITICAL remains blocking. Local and rejected
  outputs retain complete diagnostic decisions separately from canonical membership.
- `npm run ci` passed all **174 tests** (153 actions, 21 local), including generated
  source checks. `git diff --cached --check` passed.
- Four packages generated through the actual TypeScript writer passed the independent
  Python reader at environments `dc04e29`: not affected, accepted risk, clean, and
  unused expired policy. **165 focused environments tests** passed with frozen offline
  execution, including historical validation, acquisition and current-admission cases.
- Security, contract/design and maintainability reviews found no remaining material
  issues after fixing a summary-size failure on valid large approval descriptions.
  A 100-approval escaping regression preserves the pass and complete retained JSON.
- No schema/dependency/producer-pin changes, real approvals, live scans, signing,
  registry operations, workflow dispatch, admission or AWS changes were performed.
  These results establish offline behavior/package consistency, not live acceptance.

For repeatable interoperability, run the synthetic fixture generator with a new
temporary output directory:

```sh
node test/support/generate-v3-package.mjs /tmp/actions-v3-interop-new
```

From the reviewed environments checkout, verify each generated scenario's `package`
directory with `uv run --frozen --no-sync python -m movie_platform_automation.candidate_evidence_package`
and `--component recommendation-mcp --evidence-version v1alpha3 --package-directory <path>`.
The generator uses only synthetic fixtures and a fake GitHub transport. The reader
performs no signature verification or current-policy acquisition in this exercise.

## 2. Goals

- Preserve every original finding and raw severity count.
- Block every CRITICAL without a current, exact, valid approval at evaluation.
- Produce independently verifiable historical v3 decisions in the four-file package.
- Give local/PR diagnostics the same policy decisions without admission authority.
- Preserve legacy invocation, strict behavior, profiles, and producer pins.

## 3. Non-goals

No real approval records, producer pin changes, component onboarding, environment
workflow activation, merges, publication/admission dispatch, image copies, AWS
changes, or live acceptance exercises. No new exemption schema or runtime dependency
is proposed. Do not modify sibling worktrees or their stored drafts.

## 4. Current State

Read-only verification on 2026-09-14 established:

- Actions local HEAD and remote main: `6c979fd00330b47e927f5df45291add6439b1720`.
- Environments local HEAD and remote main: `dc04e29a8de19ad2c79e1473ea54fbaaa2cec610`.
- Both inspected main working trees were clean before planning.
- Environments #91 merged at `dd1a2a9d5f3fdd293fbfb38e1409a217c25318f9`;
  #93 at `a20c12a287c2e242d186cf958ba1d30ba911355f`.
- Environments main also contains #95's read-only current-policy diagnostics.
- `npm run ci` passed: 95 actions tests and 13 local-tool tests, with generated
  JavaScript matching source. These are baseline results, not runtime integration proof.
- The exemption schema, v3 candidate schema, and shared `admission-cases.json`
  agree between repositories (schemas compared as JSON; fixture bytes match).

The existing `vulnerability-policy.mts` is pure and unused by live entrypoints.
`evaluate-vulnerabilities.mts` and `write-candidate-evidence.mts` independently
reject any raw CRITICAL. The local `scan.mts` subprocess-output parser assumes a
successful result implies zero CRITICALs. Hosted metadata emits only v1alpha2.

Environments explicitly supports v3 package/retrieval/trust/admission selection;
its hosted workflows retain legacy defaults. Its reader recomputes the historical
decision and later admission independently acquires current policy once. Merging
the reader does not activate hosted v3 admission.

PR #9 is historical foundation context. Actions #12 superseded its historical/current
approval equality and separate exemption opt-in handoff. The reviewed contract in
`docs/vulnerability-exemption-contract.md` is authoritative for this integration.

## 5. Requirements and Assumptions

### Confirmed Requirements

V3 automatically uses approved-policy evaluation. Missing or failed policy loading
must not become an empty list. Preserve exact CVE/PURL/package/platform matching,
30/90-day lifetimes, unused/expiry warnings, HIGH behavior, and no source-commit lock.
Admission may use a renewal or replacement without rewriting producer evidence.

### Runtime Selection

- Add closed `evidence-version: v1alpha2 | v1alpha3` selection, defaulting to v1alpha2.
- Local v3 selection requires an explicit allowlisted component; existing local
  invocations remain strict without credentials or policy acquisition.
- Acquire fixed approved actions main once for each v3 scan/evidence evaluation,
  freezing its SHA and selected component records for that decision.
- Use existing caller token capability for hosted acquisition; local v3 requires
  authenticated read access. The local scanner receives no token. Hosted scanning
  mounts a temporary GHCR-only Docker auth file read-only into the pinned Trivy container;
  policy acquisition happens in Node outside that container.

### Confirmed Producer Policy Source

During the scope interview, the user selected the recommendation: "use the latest
approvals." Hosted and local v3 scans resolve the fixed central repository's approved
main once per evaluation and freeze that revision for the decision. Reviewed approvals
and withdrawals take effect on the next scan without producer implementation-pin
updates. Retrieval failure blocks the check; no bundled, cached or empty fallback.
Admission still independently retrieves current approved main for its own attempt.

The source-selection question is resolved. Rollout preserves existing invocations
and requires explicit v3 selection in the separately reviewed service migration.
No unresolved contract question remains from the interview.

No candidate/record field changes are currently needed. Version selection is a
compatibility mechanism, not an additional exemption enable switch.

## 6. Proposed Design

### Acquisition and authority

Add a narrow actions-owned acquisition adapter with fixed repository, branch and
component paths. Follow the same
Git-object protocol as environments: main ref, immutable commit/root tree,
`security-exemptions` tree, selected component tree, exact record blobs. Complete
parent listings may establish absent component policy. A missing policy root,
failed request, truncated listing or invalid selected record must fail.

Validate regular non-executable `EX-ID.json` members, filename/ID equality, exact
Git blob bytes, UTF-8, unambiguous JSON, selected component and duplicate/conflicting
records. Retain expired records for evaluator diagnostics. Bound requests and total
time; disallow arbitrary endpoints, redirects to other authorities, caches and
credential/configuration inheritance that can redirect requests. The implementation
uses Node's HTTPS transport with a fixed API host, explicit authentication/TLS,
response byte bounds and a total deadline, without new dependencies or CLI setup.

### Hosted composition

Keep version dispatch explicit in `action.yml` and executable adapters. The v3
composition should acquire once, evaluate the complete bounded report once at a
whole-second UTC time, render diagnostics, and construct candidate evidence from
the same validated report, snapshot and decision. Prefer composing these operations
in one executable over passing caller-editable policy/result files between steps.
The writer must enforce zero blocking CRITICAL and report/subject/hash agreement;
it must never trust a previous step's success flag as authorization.

Retain the existing provenance verification and hosted-runner enforcement before
canonical output. Attest/upload exactly four files with the version-selected candidate
filename. Keep policy staging and diagnostic-only files out of canonical membership.
Failed evaluation retains the original report and full diagnostic decisions in the
rejected artifact, never a success-looking candidate package.

### Complete scanning and local behavior

Inspect and control the actual pinned scanner execution, including default config,
ignore files, VEX/rego/status filters, skipped files/packages and inherited `TRIVY_*`
settings. Merely adding `ignore-unfixed: false` is insufficient: the pinned
trivy-action deliberately defers some default-valued inputs to environment/config.
Use controlled configuration and execution context with explicit full-report settings.
Exemptions must only be applied after the original report is complete.

Extend local `scan.mts` with closed version/component selection and the shared v3
acquisition/evaluation path. Retain Docker image-ID/platform checks and complete
report output. Add full machine-readable policy diagnostics, distinguish `passed`
from `passed-with-exemptions`, and retain exit 0 / policy failure 1 / operational
failure 2. Local and PR diagnostics must never write signed/canonical evidence.

## 7. Alternatives Considered

| Choice | Decision |
| --- | --- |
| Replace legacy defaults with v3 immediately | Reject: consumer hosted activation is separate and legacy compatibility is required. |
| Closed version dispatch with strict default | Recommend: bounded adoption without changing current callers. |
| Reimplement exemptions in writer/local helper | Reject: creates multiple policy implementations. |
| Shared evaluator with narrow runtime adapters | Recommend: existing reviewed semantics remain the single TypeScript policy. |
| Persist arbitrary policy JSON between workflow steps | Avoid: increases source-authentication and tampering obligations. |
| Compose v3 acquisition/evaluation/writing in one process | Prefer: one snapshot/time and no new approval handoff artifact. |

## 8. API / Interface Changes

- Hosted: optional closed `evidence-version`, legacy default retained.
- Local: `--evidence-version v1alpha3 --component <allowlisted-component>`.
- V3 evaluation output supports `passed-with-exemptions`, original counts,
  exempted counts by type, blocking count, used approvals and warnings.
- No caller-selectable exemption path, repository, URL, revision, signer or bypass.
- Existing legacy output parsing remains compatible; v3 gets explicit dispatch.

## 9. Data Model / Persistence Changes

Use the existing v3 candidate schema unchanged. Persist actual used records and
the scan-time decision inside the signed candidate, with fixed source repository,
resolved policy revision and original report hash. No fifth canonical artifact.
Local/rejected diagnostics have distinct filenames and no admission semantics.

## 10. Security, Privacy, and Abuse Considerations

Test malicious producer scanner configuration and policy lookalikes, failed acquisition,
ambiguous JSON, wrong Git identity, unsafe paths/symlinks, oversize files and output
tampering. Preserve workspace/temp containment, exclusive writes, safe annotations,
credential isolation, provenance checks and allowlisted publication identities.
Do not expose process stderr, tokens, private configuration or attestation bundles.

## 11. Performance, Scalability, and Reliability Considerations

Keep contract limits: 128 records, 16 KiB canonical record, 4,096 result groups,
10,000 findings, 768 KiB compact evaluation and 1 MiB complete v3 candidate bytes.
For current-main acquisition, match the environments adapter's 120-second total
budget, 1 MiB metadata responses, 4,096 tree entries, 64 KiB raw record and
128 KiB blob response limits. No retries or fallback inventory.

The environments package reader allows 4 MiB provenance and 16 MiB each for SBOM
and report. Enforce these for canonical v3 generation rather than the current
writer's generic 64 MiB bound. Local scanning may retain its existing 64 MiB report
ceiling, with clear explanation when a report cannot be packaged downstream.
Check raw byte limits before parsing and actual final serialization before writing.
Never truncate a decision or raise limits silently; point failures to the local path.

## 12. Implementation Steps

1. Document the confirmed latest-main producer source and closed version defaults.
   Targets: this plan, `docs/vulnerability-exemption-contract.md`.
2. Implement bounded policy acquisition and safe JSON/file adapters.
   Targets: focused new modules under `actions/container-evidence/src/`, new
   adapter tests under `test/`. Verify fake transport failures and proven emptiness.
3. Add the v3 evaluator/writer composition and explicit profile/version dispatch.
   Targets: `evaluate-vulnerabilities.mts`, `write-candidate-evidence.mts`,
   `profile.mts`, `context.mts`, and focused helper/entrypoint modules as needed.
   Verify exact subjects, raw counts, blockers, serialized limits and exclusive writes.
4. Wire controlled hosted scans, canonical four-file membership and rejected diagnostics.
   Targets: `actions/container-evidence/action.yml` and scanner adapter/config files.
   Verify hostile config/environment cannot hide findings or emit canonical failure output.
5. Integrate local v3 scanning and retained policy explanations.
   Targets: `local-tools/container-security/src/scan.mts`, `trivy-runner.mts`,
   dedicated local tests. Verify legacy invocation and exit meanings.
6. Add a synthetic generated-package interoperability exercise against the pinned
   environments main reader and existing current-decision fixtures. Ordinary actions
   CI remains self-contained/offline; it must not require a sibling checkout.
7. Update hosted/local runbooks and rollout status, regenerate both `lib/` trees,
   run required checks and prepare the `[ai]` PR without consumer changes.

## 13. Testing Strategy

Use actual generated JavaScript, temporary directories and fake transports/scanners.
Cover strict legacy behavior; exact-scope approved and unapproved CRITICALs; mixed
approved/blocking reports; missing PURLs; malformed/expired/future/duplicate policy;
policy-source tampering; source acquisition failures; same findings local/hosted;
all finding pointers/counts/warnings retained; escaped/bounded summaries; exact
four-file package membership; altered report hashes/evaluation records; all limits.

Cross-check generated v3 packages with the independent Python historical reader,
including unused warnings, whole-second evaluation time <= generatedAt, raw counts,
record hashes, exact subject and file hashes. Exercise renewal/replacement/withdrawal
through synthetic current-decision fixtures without registry work. Do not describe
offline package consistency as signature or live admission acceptance.

Required actions checks: `npm run ci` and `git diff --check`; install with
`npm ci --ignore-scripts` only if needed. Run focused downstream offline verification
using its frozen environment. Do not dispatch workflows for validation.

## 14. Rollout / Migration Plan

Merge/adoption are outside this task's authority. Prepare reviewable code first.
Later producer adoption must coordinate explicit v3 selection with environments
hosted workflow activation. Keep legacy defaults until then. Existing 14-day
candidate/rejected retention and evidence discovery documentation remain in place.
Rollback is reverting the consumer's reviewed full-SHA action pin and coordinated
version selection, restoring strict CRITICAL gating. Approvals remain separate PRs.

## 15. Risks and Mitigations

| Risk | Mitigation |
| --- | --- |
| Scanner suppresses findings before evaluation | Controlled execution/configuration and adversarial adapter tests. |
| Self-declared policy treated as authority | Fixed authenticated source, immutable acquisition and no caller policy paths. |
| Writer bypasses the gate | Reuse validated decision/report in one composition; writer enforces blockers. |
| Producer outputs packages too large for admission | Enforce downstream per-member bounds and actual candidate bytes. |
| V3 producer activated before hosted consumer | Explicit version selection, unchanged defaults/pins and documented dependency. |
| Renewed approval rejected against historical record | Preserve independent historical/current decisions and shared vectors. |

## 16. Done Criteria

Hosted and local v3 use the reviewed evaluator; complete findings survive; any
unapproved CRITICAL blocks; acquisition fails closed; legacy tests pass; generated
packages pass independent historical verification; diagnostics cannot masquerade
as admission; generated source and documentation match; no prohibited operations.

## 17. Review Checklist

- [x] Repository state and current downstream implementation inspected.
- [x] Superseded PR #9 assumptions distinguished from the reviewed contract.
- [x] Proposed scope, alternatives, limits, testing and rollout documented.
- [x] Producer policy snapshot choice settled: latest approved main per scan.
- [x] Runtime implementation and adversarial adapter tests complete.
- [x] Generated-package interoperability and required checks complete.
- [x] `[ai]` commits and [PR #13](https://github.com/movie-reservation-platform-lab/movie-platform-actions/pull/13) prepared with accurate validation limits.

The follow-up [review findings and reading guide](governed-exemption-runtime-review.md)
record the four specialist reviews, new-teammate clarity refactor and verification.

## 18. Handoff Prompt for Implementation Agent

The requested scope interview is complete. Continue implementation/review for actions #5.
Use latest approved main for producer policy. Preserve legacy defaults, all original findings, exact trust identities,
strict unapproved-CRITICAL blocking and non-admissible local/PR diagnostics. Use the
existing pure evaluator and unchanged v3 schema. Keep I/O in focused adapters and
tests offline. Recheck main and local changes before branching. Regenerate `lib/`
from TypeScript, run `npm run ci`, and verify synthetic generated packages against
the reviewed environments reader. Use `[ai]` commit/PR prefixes. Do not approve
exemptions, change producer pins, merge, dispatch publication/admission, copy images
or change AWS. Revisit only concrete contract discrepancies discovered in code.
