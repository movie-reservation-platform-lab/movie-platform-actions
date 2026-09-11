# Implementation Plan: Governed VEX Container Vulnerability Exemptions

Status: PR1 foundation implemented; PR2 verification and PR3 runtime integration remain pending.
Issue: https://github.com/movie-reservation-platform-lab/movie-platform-actions/issues/5
Branch: `issue-5-governed-vex-exemptions`
Base: fetched `origin/main` at `7d8cadf6f5fab9e76abec43a701c19b87650eb11`.

## PR1 Implementation Record

The user authorized PR1 after the 12-topic review. Added the two schemas, four
focused pure modules (including small shared value checks), shared decision
fixtures, synthetic v1alpha3 example, governance/contract docs, PR template,
CODEOWNERS entries, and the GitHub `security-exemption` label. No active approvals
were added. Existing hosted/local entrypoints, v1alpha2 schema, and dependency
manifests are unchanged.

Frozen details: one explicit OpenVEX component-repository product and versioned
package subcomponent; whole-second UTC dates; deterministic sorted-key compact
JSON record hashes; exact PURL bytes with encoded-version/Debian-epoch checks;
128 selected records, 16 KiB compact record, 10,000 findings, 768 KiB evaluation,
and 1 MiB v1alpha3 candidate limit. Full semantics and Python handoff are in
`docs/vulnerability-exemption-contract.md`. The new candidate limit must be
implemented in the downstream reader and integration writer; a schema alone
does not enable it.

Verification: `npm run ci` passes all 100 tests (52 foundation tests plus the
existing 48), including generated-source checks. No live scanner/publication/admission check was performed, and
#84/#85 and producer worktrees were not modified. PR2/PR3 remain separate work.

## 1. Summary

Add centrally approved, expiring vulnerability exemptions without hiding original
findings. Use one JSON record per component/CVE/exact versioned package, containing
OpenVEX plus platform approval metadata. Share a pure TypeScript evaluator across
local/PR/publication adapters; independently verify in Python at admission.

Publish exception-aware evidence as v1alpha3, retaining the four-file package.
Admission checks embedded approvals against its own reviewed policy revision.
Deliver two PRs here and one in environments, with separate producer adoption
and actual exemption-request PRs. This plan does not approve any vulnerability.

## 2. Goals

- Fail every unapproved CRITICAL finding; preserve strict defaults and HIGH behavior.
- Support both non-applicability and explicit acceptance of genuinely applicable risk.
- Retain original reports/counts and make exemption-assisted passes obvious.
- Bind decisions, approval details, and policy identity into signed exact-image evidence.
- Preserve independent admission validation, expiry, and operator-driven revocation.
- Keep the implementation and human review process small enough for this lab.

## 3. Non-goals

- Approving current Perl/MCP findings or treating scanner suppression as proof.
- Source-commit locking, automatic reachability analysis, or reapproval per rebuild.
- A separate policy repository/package, generic policy engine, or reminder service.
- Global CVE/package bypasses, raw producer ignore files, severity reduction, or
  automatic trust of latest main.
- Folding existing producer, environments #84/#85, or infra #52 work into this issue.
- Live publication, workflow dispatch, IAM changes, admission, or deployment without
  separate explicit authorization.

## 4. Current State and Rollout Context

### Repository evidence

- `actions/container-evidence/src/evaluate-vulnerabilities.mts` validates a Trivy
  report and subject, writes counts/summary, and rejects CRITICAL findings.
- `write-candidate-evidence.mts` independently recounts and rejects CRITICAL.
- `actions/container-evidence/action.yml` scans an exact published digest, evaluates,
  writes evidence, attests four exact files, and separates rejected diagnostics.
- `contracts/component-candidate-evidence-v1alpha2.schema.json` is closed.
- `profile.mts` owns allowlisted component/publication identities.
- `local-tools/container-security/src/scan.mts` invokes the evaluator and parses
  an exact output shape, currently assuming a pass means zero CRITICAL findings.
- Sources compile to checked-in ESM. Runtime dependencies are currently absent;
  existing AJV dependencies are development-only.
- Offline tests live in `test/`; local-helper tests have their own
  `local-tools/container-security/test/` directory.
- CODEOWNERS names the maintainer. Effective main rules inspected on September 11
  required CI, not independent owner approval. The user confirms they are currently
  the only organization member and expect to add others.

### User-supplied rollout snapshot (September 11; not all statuses reverified)

| Work | Context supplied by user |
| --- | --- |
| actions #2 | Merged shared-action foundation; supersedes organization .github #13 |
| recommendation-mcp #9 | Merged; subsequent main publication failed the vulnerability gate |
| recommendation-mcp #10 | Remediation; local `ai/container-security-pr-gate` work is separate |
| web #16, recommendation-service #10, reservation-mcp #9, agent #17 | Remaining producer PRs; replace older PR numbers in prior handoffs |
| infra #52 | Admission IAM expansion; applying it remains a separate operator deployment |
| environments #84 | Multi-component evidence/admission foundation |
| environments #85 | Local launcher protected-admission adoption, stacked on #84 |

The handoff describes main run 34474678097 pushing an image before five CRITICAL
findings blocked evidence. It also describes a Trixie multi-stage remediation
image with three remaining perl-base findings. These are historical observations,
not new measurements or approved exemptions. Preserve the separate producer
worktree and do not treat green PR checks that skip publication as image-policy proof.

Read-only remote checks during topic 12 confirmed #84 and #85 open:
#84 head `6b106ba6d52db11e9cf43e8d1ef4b2ea91df0c1a`, base main;
#85 head `621cb64b1fd7fdad89524ba1bc287c42e822deda`, base
`ai/all-container-admission`. #84's body still contains older dependency references.
No comments, PR edits, or merges were performed.

Inspected #84's `container_candidate_profiles.py`: exact four-file membership,
v1alpha1/v1alpha2 document names, and a 64 KiB candidate-document limit.
Its `candidate_admission/policy.py` still rejects any CRITICAL count.
The new reader must address these and intermediate trusted-receipt contracts,
not merely add a schema. Do not infer remote branch contents from the sibling
local checkout alone.

## 5. Confirmed Requirements, Decisions, and Remaining Detail

All 12 topics were reviewed one at a time; multiple rounds stayed on the same topic.

| Topic | Agreed decision |
| --- | --- |
| 1 | Dedicated central folder here; exemption PR template and label. Separate repository deferred until review volume warrants it. |
| 2 | Both non-applicability and risk acceptance from the initial release. |
| 3 | Separate component + exact CVE + exact versioned PURL records. Shared analysis and multiple records in one PR allowed. |
| 4 | Maximum 30-day risk acceptance / 90-day non-applicability; reviewed renewal, expiry at evaluation and admission, manual early revocation. User is current approver, including own requests. |
| 5 | v1alpha3; four files with approvals/decisions embedded in the signed candidate document. Admission owns an independently reviewed policy pin. |
| 6 | Standard OpenVEX block plus platform approval fields in one JSON record. |
| 7 | No source-commit lock. Ordinary application changes do not cancel an in-scope time-boxed approval; stale-analysis risk is acknowledged. |
| 8 | Shared TypeScript policy here, independent Python verification downstream, common fixtures; explicit exemption opt-in. |
| 9 | Clear raw/exempted/blocking counts; warnings for every used approval; seven-day expiry-soon warning in existing output. |
| 10 | Unused expired record warns; expired approval cannot unblock a present finding. Malformed/conflicting selected policy fails explicitly. |
| 11 | Focused offline policy/contract/adapter tests; local tests remain separate. Live checks separately authorized. |
| 12 | Actions foundation PR, environments verifier PR, actions integration PR; producer adoption and real approvals separate. |

Important steering: the user rejected the proposed per-source-revision binding
because it would make the 30/90-day approval workflow painful. Do not reintroduce it.

The policy decisions and PR split are agreed; implementation authority currently covers PR1 only.
Exact field names, validation limits, and adapter mechanics are engineering work
inside the scoped PRs below. Before freezing PR1's contract, settle explicit VEX
product/subcomponent mapping, record equality/content identity, and representative
Trivy PURL fixtures. Before PR2/PR3, settle trusted snapshot loading/provenance,
closed version selection, intermediate receipt fields, and bounded document sizes.
If those details require a different user-visible policy or new dependency, reopen
that specific topic rather than silently changing the design.

## 6. Proposed Design

### Central governance

Use `security-exemptions/<component>/` with one JSON record per exact approved
finding/package scope. Add
`.github/PULL_REQUEST_TEMPLATE/security-exemption.md`, proposed GitHub label
`security-exemption`, and CODEOWNERS coverage. No existing exemption template
or label was found. Create them only in the implementation phase.

The PR captures request/renewal/removal intent, rationale, primary references,
owner, expiry, and an explicit approval decision. Metadata or a label alone is
not authorization. The trusted maintainer-approved revision is the authority
source. The single-maintainer model does not claim independent review.
Document an ownership/merge-permission review when collaborators join.

### Record contract and VEX

Create a versioned closed platform record containing:

- Stable exemption identity, component, and approval type.
- Exact vulnerability identifier and versioned package PURL, retaining relevant
  qualifiers; declared platform and any supported machine-checkable scope.
- Owner, creation/approval timestamps and approval reference, mandatory expiry.
- Human-readable rationale and primary advisory/analysis references.
- OpenVEX v0.2.0 metadata and one explicit statement for the scoped product/package.

Non-applicability maps to OpenVEX `not_affected` with a supported justification.
Risk acceptance retains `affected` and its action statement; platform fields
carry the permission to accept risk. Never invent a VEX impact status meaning
“risk accepted.” An approval explains an assessment made at approval time; a
new scan must not silently refresh that assessment's timestamp.

OpenVEX explicitly supports embedding. Use a narrow profile rather than generic
JSON-LD resolution, implicit history merging, arbitrary aliases, or network
context loading. Define and test the relationship between component/product and
affected package/subcomponent; do not accidentally publish a service-specific
assessment as a universal statement about the package.

Suggested contract filenames:
`contracts/container-vulnerability-exemption-v1alpha1.schema.json` and
`contracts/component-candidate-evidence-v1alpha3.schema.json`.
Pin/reference the reviewed standard profile in documentation; existing v1alpha2
schema and legacy semantics remain unchanged.

### Pure evaluation and exact matching

Proposed focused modules under `actions/container-evidence/src/`:
`trivy-report.mts`, `exemption-policy.mts`, and `vulnerability-policy.mts`.
Names can be adjusted to existing conventions without adding architectural layers.

Inputs are validated report facts, component/platform context, validated trusted
records, explicit opt-in, and an explicit evaluation time. Return original counts,
per-finding dispositions, exempted counts by type, blocking CRITICAL count,
warnings, and a policy result. Keep filesystem, process, environment, and summary
writing in executable adapters. No new runtime dependency is selected by this plan.

- Match exact component + vulnerability + versioned PURL + declared platform.
- Missing/invalid package identity cannot authorize an exemption; no package-name
  fallback, wildcard versions, or implicit cross-service reuse.
- Duplicate/conflicting selected records fail; do not choose an arbitrary winner.
- A changed source commit alone does not invalidate approval.
- A new CVE or changed package version needs its own approval if CRITICAL.
- Expiry cannot authorize a finding. A well-formed unused expired record only warns.
- Malformed loaded policy fails even if apparently unused; evaluate only the selected
  component at runtime, with repository checks covering all committed records.
- Keep HIGH/non-CRITICAL behavior unchanged. An unused record must not create a HIGH gate.
- Do not automatically reset approvals just because the scanner DB updates; current
  findings still undergo exact matching. No live advisory revalidation is proposed.

Preserve complete scanner JSON. Do not feed exemptions into Trivy as suppression
input. Human review remains responsible for applicability reasoning; CI does not
prove code absence or reachability. Known stale analysis can be withdrawn through
the manual process, but is not automatically detected by this implementation.

### Lifetime and diagnostics

Use explicit UTC timestamps and current-time checks. At or after expiry, an
approval is unusable. Approval lifetime is at most 30 days for accepted risk,
90 days for non-applicability; shorter periods are allowed. Renewal requires a PR.

Show “pass with exemptions” distinctly, with raw CRITICAL, exempted-by-type, and
blocking counts. Show each used exemption's identity/type, component, CVE/package,
owner, and absolute expiry. During the final seven days, add an expiry-soon warning,
not an early failure. No scan means no reminder; no scheduled job is included.

Invalid/operational results must never print a policy pass. Retain full machine-readable
dispositions in the hosted candidate document or dedicated local diagnostic output.
Bound annotations/summaries and link to complete retained diagnostics when necessary.

### Opt-in and adapter behavior

Hosted action: add `use-approved-exemptions`, default false, alongside the existing
closed component selection. Local helper: proposed
`--use-approved-exemptions --component <component>`. Preserve existing strict usage.

Select records from the trusted action/policy revision, not a producer-chosen file,
URL, repository, or arbitrary revision. PR-time checks use the same policy but are
not admissible evidence. Local checkout edits can only produce diagnostic results;
the local helper does not authenticate publication authority.

Update the local evaluator-output parser: a successful policy result may now have
nonzero raw CRITICAL counts. Preserve documented local success/policy-failure/
operational-failure exit distinctions. Update both hosted evaluator and writer
through the shared policy functions, not independent exemption implementations.

### Signed package and independent admission

Keep four files: v1alpha3 candidate evidence document, image provenance, SBOM,
and original Trivy report. Embed only relevant approval records and decisions,
including source revision/content identity, ownership, rationale, references,
and expiry, in the signed candidate document. Bind decisions to image digest
and report hash. Never redefine raw CRITICAL count to mean “unapproved count.”

Admission remains Python. Share schemas and deterministic test fixtures rather than
launch Node. It independently verifies signatures, package membership, hashes,
subject, report-derived counts/dispositions, and approvals against its own reviewed
full-SHA central-policy snapshot. A producer-declared revision is not authority.

Compare used record content/identity, not merely whether repository SHAs differ:
unchanged approvals remain usable across unrelated code/policy changes until expiry.
Changed/renewed approvals require fresh matching evidence. Removed approvals fail
after admission's trusted snapshot is updated. Snapshot retrieval must use trusted
configuration and bounded I/O; no caller-controlled source or implicit latest main.

Expiry/revocation must be checked at admission time, not just at an earlier
verification job. Intermediate trusted receipts must preserve sufficient bindings
for that check. v1alpha1/v1alpha2 paths stay strict and cannot acquire exemptions.

## 7. Alternatives Considered

| Alternative | Decision / tradeoff |
| --- | --- |
| Separate policy package/repository | Deferred; central folder is sufficient now. |
| Global exact-CVE/PURL approval | Rejected; service-specific records make ownership and scope explicit. |
| Shared multi-service record with overrides | Not selected; repeated metadata is simpler than inheritance. |
| Non-applicability only | Rejected; both types needed for this lab. |
| Commit-locked non-applicability | Rejected by user; accepts stale-analysis risk within the approval window. |
| In-place v1alpha2 extension | Rejected; closed schema and changed pass semantics need v1alpha3. |
| Separate signed decision file | Not selected; embed decisions to preserve four-file membership. |
| Entirely custom applicability format | Not selected; OpenVEX plus governance fields meets the need. |
| Signature/expiry alone at admission | Insufficient for early revocation; use independently pinned approved records. |
| One cross-language evaluator runtime | Not selected; independent Python plus shared fixtures avoids Node coupling. |

## 8. API / Interface Changes

- New exemption-record schema and v1alpha3 candidate schema; no in-place v1alpha2 weakening.
- Explicit hosted/local exemption opt-in and local component selection.
- Evaluator output must distinguish raw counts, exemptions, and blocking findings.
- New candidate-document filename in exact upload/attestation/reader membership.
- Admission-owned policy revision configuration and version-aware trusted receipt data.
- No arbitrary ignore-file interface, new service, or automatic approval mechanism.

## 9. Data Model / Persistence Changes

Versioned JSON policy records and embedded signed decision evidence; no database.
New candidate format retains four files. Keep supported old schemas/fixtures.
Record identity/comparison and bounded document layout must be frozen with PR1
fixtures before downstream implementation depends on them.

## 10. Security, Privacy, and Abuse Considerations

Maintain closed component/repository/signer/path selection, trusted provenance,
regular-file containment, exclusive writes, bounded reads, and rejected-evidence
separation. Sanitize human-facing text and never expose raw child stderr/tokens.

Audit Trivy configuration and environment sources so producer-local ignore/config
behavior cannot remove findings before evaluation. Keep full severity reporting and
the existing scanner pin/settings. No advisory URL is executed or fetched as policy.

Approval fields are not authenticated identities by themselves. Trusted revision
selection, approval-content comparison, and exact signed subject/report bindings
must all be enforced. Separate runtime scanning is a desired future complementary
control, not verified existing coverage or an excuse to weaken these checks.

## 11. Performance, Scalability, and Reliability

Reuse existing subprocess/report limits. Introduce bounded policy-record counts,
file/string sizes, and a bounded v1alpha3 document; coordinate writer and reader
limits. #84 currently caps that document at 64 KiB, which must not be silently
exceeded by embedding records. Select explicit tested limits with PR1 fixtures.

Avoid unbounded matching, retries, and network discovery. No dependency on live
advisory availability. Opted-in policy-source errors fail explicitly, not via a
silent policy fallback. Use a supplied clock in tests, not sleeps.

## 12. Implementation Steps and PR Boundaries

### PR1 — actions foundation, on the current issue branch

1. Freeze the narrow exemption/v1alpha3 schemas and example field mapping under
   `contracts/`; preserve v1alpha2 unchanged. Add shared decision fixtures under
   `test/fixtures/vulnerability-policy/` and AJV schema/fixture checks.
2. Add focused pure report/record/decision modules under
   `actions/container-evidence/src/`, with succinct module/function documentation,
   generated `lib/`, and focused tests. Existing executable adapters keep their
   behavior until PR3; prove this with the existing regression suite.
3. Add `security-exemptions/README.md`, component directory conventions, the
   exemption PR template, CODEOWNERS coverage, and the requested label. Synthetic
   examples belong in fixtures/docs, not active approvals of real findings.
4. Document request/review/renewal/removal and snapshot identity. No new runtime
   dependency without a justified plan update.
5. Verify `npm run ci` and `git diff --check`; identify generated output separately
   in review. This PR must not require environments #84/#85 to merge first.

### PR2 — environments verifier, separate from existing #84/#85

1. Start from the reviewed #84 foundation (prefer after it merges; otherwise
   explicitly agree a stack). Do not silently amend #84 or #85.
2. Extend `container_candidate_profiles.py`, `candidate_evidence/schema_validation.py`,
   `candidate_evidence/compatibility.py`, and `schemas/` for closed v1alpha3 support,
   exact four-file layout, and supported strict legacy paths.
3. Add focused Python policy/snapshot adapters and consume PR1's reviewed schemas/
   fixtures. Inspect/update `candidate_evidence_package/policy/vulnerability_report.py`,
   `candidate_evidence_package/verification.py`, and candidate-evidence validation.
4. Trace `candidate_evidence_attestation/` result/handoff schemas into
   `candidate_admission/trusted.py`, `candidate_admission/policy.py`, and preflight
   CRITICAL checks. Preserve decision bindings and recheck expiry/revocation at
   final admission, rather than bypassing gates because an earlier step passed.
5. Add reviewed policy-source configuration and bounded trusted snapshot loading;
   no caller-selected source. Cover archive/file membership, tampering, record
   changes, wrong subjects, and legacy receipts in corresponding `test/` suites.
6. Run the downstream frozen-environment pytest/Ruff commands and existing bindings/
   example validation checks. Read that repository's current guidance first.

### PR3 — actions integration

1. Update `evaluate-vulnerabilities.mts`, `write-candidate-evidence.mts`,
   `profile.mts` as needed, and `action.yml` to use shared evaluation, explicit opt-in,
   complete diagnostics, exact v1alpha3 attestation/upload membership, and safe
   scanner configuration. Regenerate `lib/`.
2. Update `local-tools/container-security/src/scan.mts`, local generated output,
   and its dedicated tests for explicit component/opt-in, outcomes, and warnings.
3. Update `docs/container-candidate-actions.md`, local runbook/helper README,
   and producer PR-check integration instructions. Run full local CI.
4. Require the compatible reader before enabling v1alpha3 production in consumers.
   Validate actual changed source/schema/test size; do not conceal review size in
   generated files or fold unrelated cleanup into these PRs.

## 13. Testing Strategy

Use shared language-agnostic fixtures with fixed evaluation times:

- Both types; strict default; exact match and other-component/CVE/package/version failures.
- Source changes alone preserve in-scope approval; original assessment dates remain intact.
- Expiry instant, 30/90-day limits, seven-day warnings, reviewed renewals, unused expiry.
- Invalid fields, missing owner/reference, ambiguity/conflicts, malformed selected policy.
- Current trusted snapshot acceptance; removed/changed approvals and untrusted source rejection.
- Original findings retained; correct raw/exempted/blocking counts; unchanged HIGH behavior.
- Subject/report mismatch, tampering, four-file membership, unsupported versions, strict legacy behavior.

Use temporary files/fake executables for adapter tests, exercising checked-in JS.
Keep local-helper tests dedicated; do not repeat every policy permutation through
every CLI wrapper. No live registry, GitHub attestation, Trivy, or AWS calls in
ordinary tests. Offline fixtures do not constitute live admission acceptance.

Actions verification: `npm run ci`, `git diff --check`.
Downstream verification: `uv run --frozen --no-sync pytest`,
`uv run --frozen --no-sync ruff check .`,
`uv run --frozen --no-sync ruff format --check .`, plus repository-prescribed
executor bindings and example release validation. Recheck instructions when entering it.

## 14. Rollout, Migration, and Rollback

The existing producer/admission rollout and this exemption feature are related
but distinct. Code readiness does not make any candidate admissible.

- PR1 can proceed independently of #84/#85 and the unresolved MCP findings.
- #84 supplies the downstream foundation; merge it before retargeting/revalidating
  #85. This plan authorizes neither operation.
- New PR2 extends that foundation. #85 need not be folded into or blocked on VEX
  development for code review, but newly selected exempted images require the
  updated verification/admission path and compatible receipts.
- Complete the new reader before producers emit v1alpha3 through PR3/adoption.
- Remaining producer PRs are web #16, recommendation-service #10, reservation-mcp #9,
  and agent #17 per the supplied handoff; recommendation-mcp #9 already merged.
  Refresh actual statuses/pins before acting. Old #84 dependency numbers are stale.
- Producer adoption PRs enable PR-time production-image scans and update reviewed
  action pins/opt-in. Do not equate green publication-skipping PR checks with
  vulnerability acceptance. Inspect each production image.
- Real exemptions require separate reviewed requests. Installing this capability
  alone will not unblock the current Perl findings.
- Obtain fresh successful canonical main evidence for each candidate selected for
  admission. Historical summary-only output and rejected reports remain ineligible.
- Infra #52 IAM application and evidence-reader App access are separately operated
  prerequisites for live admission. Neither merging this feature nor the old PR
  set completes live acceptance.

Rollback: disable exemption opt-in to restore strict evaluation. Reverting a
consumer action pin to v1alpha2 requires a reader that still supports that strict
contract; v1alpha3 may be rejected, never reinterpreted as legacy. Do not roll
admission's trusted policy back to resurrect a withdrawn approval.

Emergency withdrawal: pause affected publication/admission, remove/withdraw the
central record through review, update producer pins and admission's trusted
snapshot, verify rejection of old evidence relying on that record, then resume.
Old configurations do not learn revocations automatically. Already-running
services are not stopped by expiry; runtime incident response is separate.

Review schema/code/test PRs before merges; all merges, dispatches, publication,
IAM/App changes, admission, and deployment require their own authorization.

## 15. Risks and Mitigations

| Risk | Impact | Likelihood | Mitigation |
| --- | --- | --- | --- |
| Producer self-authorizes suppression | High | Plausible | Trusted centrally reviewed records; independent admission snapshot |
| Evaluator/writer/Python disagree | High | Plausible | Shared TS rules, common schema/decision fixtures, adapter tests |
| Old reader rejects/misreads new evidence | High | Expected without migration | Explicit version, closed membership, reader-first adoption |
| Withdrawn approval remains in old pins | High | Plausible | Explicit operator update/pause procedure; expiry recheck |
| Analysis becomes stale after code changes | High | Plausible | Accepted time-boxed risk, dated rationale, visible warnings, manual withdrawal |
| Embedded metadata exceeds reader limits | Medium | Plausible | Agreed tested writer/reader bounds; explicit failure |
| Feature grows into the whole rollout | Medium | Plausible | Three scoped implementation PRs; existing producer/infra/admission work separate |

## 16. Done Criteria

- Reviewed contract/profile frozen with valid and invalid examples.
- Approved behavior implemented and verified in all scoped adapters/readers.
- Original reports preserved; signed approvals and counts cannot be substituted.
- Strict defaults and supported legacy verification remain intact.
- Template/label/ownership and renewal/revocation docs available.
- Generated code matches source; offline checks pass in each affected repository.
- Producer migration dependencies and any unperformed live checks are explicit.
- No real exemption or live acceptance claimed without separate evidence/approval.

## 17. Review Checklist

- [x] All 12 user-facing topics and non-goals reviewed
- [x] Alternatives and rejected source-lock proposal recorded
- [x] Security/lifecycle, tests, PR boundaries, and rollout dependencies agreed
- [x] Existing #84/#85 stacking checked without changing either PR
- [x] Concrete PR/module targets and verification commands identified
- [x] PR1 exact schema, matching fixtures, equality rules, and bounds frozen
- [ ] PR2/PR3 snapshot/provenance and receipt adapters validated against current branches
- [x] PR1 implementation authorized and completed; no runtime integration yet
- [ ] PR2 and PR3 implementation authorized and completed
- [ ] Separate rollout/live acceptance authorized where required

## 18. Handoff Prompt for the First Implementation PR

PR1 is implemented. The prompt below records its authorized boundary; do not
repeat completed work. PR2/PR3 still need separate implementation authorization.

```text
Implement PR1 (actions foundation only) from
docs/plans/governed-vex-exemptions.md.

Use issue-5-governed-vex-exemptions after checking branch/worktree state.
Preserve unrelated changes and the separate MCP remediation worktree.

Create the narrow OpenVEX-plus-governance schema, v1alpha3 schema, shared
decision fixtures, pure TypeScript evaluation modules, focused offline tests,
dedicated exemption directory/docs, PR template, and requested label.

Keep hosted/local executable behavior unchanged in this PR. No production
exemption records, no consumer pin changes, no environments #84/#85 edits,
no merges, dispatches, image publication, AWS/App changes, or admission.

Do not add a runtime dependency or change an agreed policy silently. Resolve
exact schema/product/PURL mapping, record equality, and bounded sizes with
fixtures; update the plan if facts require a material change. Preserve
application-commit-independent 30/90-day approvals and strict defaults.

Edit src, regenerate lib, run npm run ci and git diff --check. Present the
actual handwritten/schema/generated diff boundaries and downstream handoff.
Stop at the PR1 review boundary; do not automatically implement PR2 or PR3.
```

## Research References

Used KB notes (root: /home/patex1987/Documents/programming_kb):
- `concepts/API Compatibility.md`: closed-reader and semantic compatibility.
- `patterns/JSON Schema Validation Boundary.md`: validation is not authorization.
- `patterns/Choosing Clean Architecture.md`: isolate policy without speculative layers.

Primary format reference:
[OpenVEX v0.2.0 specification](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md).
Governance reference:
[GitHub code owners](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners).
Downstream context:
[environments #84](https://github.com/movie-reservation-platform-lab/movie-platform-environments/pull/84),
[environments #85](https://github.com/movie-reservation-platform-lab/movie-platform-environments/pull/85).
