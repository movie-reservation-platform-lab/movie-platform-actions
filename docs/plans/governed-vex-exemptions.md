# Implementation Plan: Governed VEX Container Vulnerability Exemptions

Status: Foundation merged in #9; reviewed contract correction is slice A of six.
Current issue: https://github.com/movie-reservation-platform-lab/movie-platform-actions/issues/11
Parent: https://github.com/movie-reservation-platform-lab/movie-platform-actions/issues/5
Branch: `issue-11-v1alpha3-admission-contract`
Base: fetched `origin/main` at `6a5af70ab18a8a93f54acde05badaef365d42d54`.

The September 14 environments review completed twelve topics and agreed six
focused PRs, with a preference for fewer where human review permits. The engineer
authorized the first implementation slice only: correct this actions contract and
add shared decision examples/tests. No producer activation or Python implementation
is part of this PR. Downstream tracking:
[environments #87](https://github.com/movie-reservation-platform-lab/movie-platform-environments/issues/87).

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

Historical foundation verification: `npm run ci` passed all 100 tests (52 foundation tests plus the
existing 48), including generated-source checks. No live scanner/publication/admission check was performed, and
#84/#85 and producer worktrees were not modified. Remaining work is now split
into the six slices in section 12 and later producer integration.

## 1. Summary

Add centrally approved, expiring vulnerability exemptions without hiding original
findings. Use one JSON record per component/CVE/exact versioned package, containing
OpenVEX plus platform approval metadata. Share a pure TypeScript evaluator across
local/PR/publication adapters; independently verify in Python at admission.

Publish exception-aware evidence as v1alpha3, retaining the four-file package.
Admission verifies the historical evidence, then independently evaluates original
findings against latest approved actions policy, acquired once per attempt.
Deliver this contract correction and five environments PRs before separate producer
integration/adoption and exemption-request PRs. This plan approves no vulnerability.

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
- Global CVE/package bypasses, raw producer ignore files or severity reduction.
- A second policy fetch/expiry gate, fresh admission scans, manual environments
  policy pins, duplicated approval inventory or indefinite audit storage.
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

Historical September 11 read-only checks during the original topic 12 found #84 and #85 open:
#84 head `6b106ba6d52db11e9cf43e8d1ef4b2ea91df0c1a`, base main;
#85 head `621cb64b1fd7fdad89524ba1bc287c42e822deda`, base
`ai/all-container-admission`. #84's body still contains older dependency references.
No comments, PR edits, or merges were performed.

The subsequent environments review verified #84 merged at
`fa6eb48daadc8404ed01e2baae4a684a7a97772b`. The historical PR snapshot above is not
an instruction to merge or retarget either PR. Existing environments worktrees
and its paused implementation draft must be preserved.

Inspected #84's `container_candidate_profiles.py`: exact four-file membership,
v1alpha1/v1alpha2 document names, and a 64 KiB candidate-document limit.
Its `candidate_admission/policy.py` still rejects any CRITICAL count.
The new reader must address these and intermediate trusted-receipt contracts,
not merely add a schema. Do not infer remote branch contents from the sibling
local checkout alone.

## 5. Confirmed Requirements, Decisions, and Remaining Detail

The foundation review and subsequent environments review were conducted one topic
at a time. This table consolidates the current decisions, superseding the original
manual-pin, approval-equality, opt-in and three-PR assumptions.

| Topic | Agreed decision |
| --- | --- |
| 1 | Dedicated central folder here; exemption PR template and label. Separate repository deferred until review volume warrants it. |
| 2 | Both non-applicability and risk acceptance from the initial release. |
| 3 | Separate component + exact CVE + exact versioned PURL records. Shared analysis and multiple records in one PR allowed. |
| 4 | Maximum 30-day risk acceptance / 90-day non-applicability; reviewed renewal, expiry at evaluation and admission, manual early revocation. User is current approver, including own requests. |
| 5 | v1alpha3; four files with historical approvals/decisions embedded in the signed candidate. Admission independently retrieves latest approved actions main once, freezes its SHA and reevaluates original findings with current approvals. |
| 6 | Standard OpenVEX block plus platform approval fields in one JSON record. |
| 7 | No source-commit lock. Ordinary application changes do not cancel an in-scope time-boxed approval; stale-analysis risk is acknowledged. |
| 8 | Shared TypeScript policy here, independent Python downstream, common fixtures; v3 evaluates approved policy automatically without an extra opt-in. |
| 9 | Clear raw/exempted/blocking counts; warnings for every used approval; seven-day expiry-soon warning in existing output. |
| 10 | Unused expired record warns; expired approval cannot unblock a present finding. Malformed/conflicting selected policy fails explicitly. |
| 11 | Focused offline policy/contract/adapter tests; local tests remain separate. Live checks separately authorized. |
| 12 | Foundation already merged. Contract correction plus five environments PRs; producer integration/adoption and real approvals separate. |

Important steering: the user rejected the proposed per-source-revision binding
because it would make the 30/90-day approval workflow painful. Do not reintroduce it.

Also agreed: no before/after drift comparison or second expiry check; a changed
policy or expiry after the current decision does not cancel that in-flight attempt.
Renewal/replacement can cover original verified findings without new producer CI.
Keep producer and admission explanations separately, with actual used approvals.
Existing 14-day admission-result retention is acceptable for this release; no
forever-storage requirement. Limits must fail clearly and be reproducible through
the existing local path. Service-registration consolidation is tracked in actions
#10 and organization .github#11; reservation-service migration is tracked in its #38.

The current authorization covers slice A only. Existing record/candidate schemas
and fixtures remain valid; new paired decision fixtures express the changed
historical/current relationship. Downstream slices must settle intermediate receipt
fields and explicit reader/writer sizes within the agreed contract.
If those details require a different user-visible policy or new dependency, reopen
that specific topic rather than silently changing the design.

## 6. Proposed Design

### Central governance

Use `security-exemptions/<component>/` with one JSON record per exact approved
finding/package scope. The foundation already added the exemption PR template,
`security-exemption` label and CODEOWNERS coverage; do not recreate them.

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
records and an explicit evaluation time. Future v3 adapters select approved-policy
evaluation automatically; the foundation's low-level boolean remains an internal
strict/approved evaluation mode, not a new user switch. Return original counts,
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

### Version selection and adapter behavior

Future hosted/local v3 integration uses closed component/version selection and
automatically evaluates approved policy. Do not add `use-approved-exemptions` or
`--use-approved-exemptions` as a separate user permission. Until that integration,
existing hosted/local entrypoints remain strict. Missing valid approval leaves
CRITICAL blocking; v3 adoption alone grants no exemption.

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

Admission remains Python. Share schemas and deterministic fixtures rather than
launch Node. Authenticate producer/signatures, exact package membership, hashes
and subject; recompute historical counts/dispositions and used-record identity at
the signed evaluation time. Historical used records are preserved, not compared
for equality against today's approvals.

Resolve fixed approved actions main to a current full SHA once per admission
attempt, then acquire selected-component records at that SHA with authenticated,
bounded I/O. A producer-declared source must not choose that authority. Failed
acquisition stops admission; never substitute a stale snapshot or empty list.
No committed environments inventory or manual policy-pin update is required.

Reevaluate original verified findings with current validated approvals and current
time once before registry work. A new/renewed/replaced approval can cover the exact
finding without new producer evidence. Missing valid coverage blocks CRITICAL.
Do not refetch or add expiry/drift checks after transfer; the next attempt observes
new policy. This does not discover new CVEs absent from the original scan.

Intermediate receipts preserve historical bindings. The final admission decision
separately records policy SHA/content identity, decision time, original evidence/
report and image digests, findings/counts and actual used approval records with
rationale/expiry. Required destination verification still precedes successful
admission proof. v1alpha1/v1alpha2 paths remain strict. Document evidence discovery
and retention; initial admission-result retention remains 14 days.

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
| Signature/expiry alone at admission | Insufficient; independently acquire latest approved policy per attempt. |
| Manual environments policy pin/inventory | Rejected; duplicate adoption work and stale approvals. |
| Historical/current approval equality | Rejected; prevents reviewed renewal without producer reruns. |
| Before/after drift or second expiry gate | Rejected; one acquisition and current decision per attempt. |
| One cross-language evaluator runtime | Not selected; independent Python plus shared fixtures avoids Node coupling. |

## 8. API / Interface Changes

- New exemption-record schema and v1alpha3 candidate schema; no in-place v1alpha2 weakening.
- Automatic approved-policy evaluation for v3; closed component/version selection.
- Evaluator output must distinguish raw counts, exemptions, and blocking findings.
- New candidate-document filename in exact upload/attestation/reader membership.
- Fixed admission policy authority with per-attempt SHA resolution and versioned receipts.
- No arbitrary ignore-file interface, new service, or automatic approval mechanism.

## 9. Data Model / Persistence Changes

Versioned JSON policy records and embedded signed decision evidence; no database.
New candidate format retains four files. Keep supported old schemas/fixtures.
Existing canonical record identity and candidate layout remain unchanged.
Historical/current decisions need not contain the same approvals. The new
environment-owned audit receipts must define explicit bounds independently of
the candidate's 1 MiB limit. No new storage infrastructure is part of this slice.

## 10. Security, Privacy, and Abuse Considerations

Maintain closed component/repository/signer/path selection, trusted provenance,
regular-file containment, exclusive writes, bounded reads, and rejected-evidence
separation. Sanitize human-facing text and never expose raw child stderr/tokens.

Audit Trivy configuration and environment sources so producer-local ignore/config
behavior cannot remove findings before evaluation. Keep full severity reporting and
the existing scanner pin/settings. No advisory URL is executed or fetched as policy.

Approval fields are not authenticated identities by themselves. Trusted revision
selection, current approval scope/validity and exact signed subject/report bindings
must all be enforced. Separate runtime scanning is a desired future complementary
control, not verified existing coverage or an excuse to weaken these checks.

## 11. Performance, Scalability, and Reliability

Reuse existing subprocess/report limits. Introduce bounded policy-record counts,
file/string sizes, and a bounded v1alpha3 document; coordinate writer and reader
limits. The legacy candidate bound is 64 KiB; the agreed v3 bound is 1 MiB.
Keep 128 selected records, 16 KiB per compact record, 4,096 result groups,
10,000 findings and 768 KiB evaluation. Each new receipt needs its own tested bound.
Enforce byte limits before parsing and structural limits before expensive work;
never truncate decisions. Explain the failing document/limit and local reproduction.

Avoid unbounded matching, retries, and network discovery. No dependency on live
advisory availability. Approved-policy acquisition errors fail explicitly, not via a
silent policy fallback. Use a supplied clock in tests, not sleeps.

## 12. Implementation Steps and PR Boundaries

The original foundation merged in #9. The following six slices supersede the old
PR2/PR3 split. Each PR carries its own tests and relevant documentation. The
engineer accepted six while preferring fewer; do not add PRs just to mirror modules.

| Slice | Repository | Scope and verification |
| --- | --- | --- |
| A (this issue #11) | actions | Correct this plan, contract, governance and README; add paired historical/current decision fixtures and tests. Keep foundation schemas, existing vectors and production runtime unchanged. Run local CI. |
| B | environments | Independent pure Python evaluation, reviewed shared contracts/fixtures and exact scope/time/hash/bounds tests. No admission wiring. |
| C | environments | Closed v3 profiles/schema registration and package validation; historical report recomputation, versioned package receipt, local CLI and tampering/legacy tests. |
| D | environments | Retrieval/attestation receipt propagation, bounded readers/writers and synthetic integration tests. Admission continues rejecting v3 until F. |
| E | environments | Narrow policy acquisition port and authenticated latest-actions adapter; fixed authority, coherent SHA/content identity, bounded input and no-fallback tests. No local approval inventory. |
| F | environments | One current admission decision, separate audit result and used approvals, existing local CLI composition, expiry/withdrawal/renewal tests and complete offline verification. |

Dependencies: A precedes contract consumption, B precedes C, C precedes D,
and F requires D and E. Implement and review one selected slice at a time.
Unsupported v3 paths stay closed between PRs; no temporary bypass to make an
intermediate PR pass. Keep repository-specific ports inward-owned, policy pure,
and external mechanics in adapters. Tests run the same underlying code locally
and in CI, with fake external systems.

After F, plan small producer integration/adoption PRs separately: update the hosted
evaluator/writer/profile and exact v3 membership, local scan helper and diagnostics,
then consumer pins. Reader support must precede producers emitting v3. Do not fold
that work, service-registration consolidation, reservation-service migration or
real approvals into these six PRs. Preserve existing environments worktrees/draft.

## 13. Testing Strategy

Retain the existing single-evaluation fixtures unchanged. Add explicit paired
historical/current cases using the same original report and distinct policy/time
inputs: renewal, replacement, current expiry and withdrawal. Expected outcomes
must be authored independently of the evaluator, not regenerated from its output.
Assert historical evidence/input immutability, current used-record details and
stable original counts/subject. Keep the existing equality-helper tests as tests
of that limited utility, not the new admission gate.

These pure cases specify decision semantics only. Python slices must additionally
prove authenticated acquisition, stale-receipt handling, one retrieval per attempt,
new-attempt refresh, malformed/oversized input, safe failures before registry work,
version isolation and success proof only after destination verification. Shared
fixtures cannot prove a transport, signature or workflow is trusted.

Use supplied time, temporary files and fake executables/transports, never live
GitHub, registry, Trivy or AWS in ordinary tests. Run existing legacy regression
suites and generated-source checks. Tests accompany every implementation slice.

Actions verification:

```sh
npm ci --ignore-scripts
npm run ci
git diff --check
```

The tests are offline; dependency installation may require network access.
Downstream uses its repository-prescribed pytest, Ruff and manifest checks.
Report command outcomes and limits; code readiness is not live acceptance.

## 14. Rollout, Migration, and Rollback

Current hosted/local entrypoints remain strict v1alpha2. Slice A changes documented
integration semantics and adds executable examples, not a public action interface.
Implementation/action pins remain reviewed full SHAs. Admission approval retrieval
is a distinct authority/freshness rule: latest approved main, resolved once to SHA.

Complete A–F before producer adoption. A valid centrally approved record is the
only exemption permission once v3 is adopted; no extra enable-exemptions switch.
No approval means a CRITICAL finding still blocks. Old producer evidence must
remain authentic and complete; summary-only or rejected reports do not become
admissible. Renewals alone do not require fresh canonical producer evidence.

If a verifier rollback leaves v3 unsupported, suspend v3 admission until compatible
verification is restored. Reverting producer implementation pins to a strict
version requires genuinely compatible evidence; never reinterpret v3 as legacy or
restore an old policy snapshot to resurrect revoked approvals.

Withdraw through review on actions main. New admission attempts acquire the updated
policy and reject findings lacking current valid coverage. No manual admission pin
update is needed. In-flight attempts keep their single decision; emergency operator
intervention and running-service incident response are separate from this feature.

Initial admission-result retention is 14 days. Document discovery and the actual
producer evidence retention separately; a digest does not preserve the referenced
artifact. Future storage work follows an actual need, not a forever-retention goal.

Do not merge, dispatch workflows, publish/copy images, mutate IAM/App/AWS resources,
admit artifacts or deploy as part of this implementation. Consumer rollout and live
acceptance remain separate release actions.

## 15. Risks and Mitigations

| Risk | Mitigation |
| --- | --- |
| Producer self-authorizes suppression | Authenticate original evidence and independently acquire fixed current actions authority. |
| Evaluators disagree | Unchanged shared vectors plus paired historical/current cases; independent Python and adapter tests. |
| Approval changes after decision | Accepted in-flight behavior; new attempt fetches again. |
| Historical approval equality rejects renewal | Reevaluate original findings using current scope/validity; preserve separate audit records. |
| Fresh policy mistaken for a fresh scan | Explicitly retain original report; new CVEs require new assessment outside this slice. |
| Old reader mishandles v3 | Closed versions and reader-first adoption; unsupported paths reject. |
| Audit artifact expires | Accepted initial retention; document limits without claiming permanent history. |
| Large PR obscures review | Six focused slices with tests/docs per slice; no automatic expansion. |

## 16. Done Criteria

For slice A: contract, governance and plan agree on reviewed semantics; paired
fixtures have explicit expected decisions and passing offline tests; runtime and
existing schemas remain unchanged; full local CI and diff hygiene pass; issue,
branch, commit and PR identify #11. Stop with the focused PR and verification
report, with no live acceptance claim or later-slice implementation.

## 17. Review Checklist

- [x] Twelve environments review topics and six PR boundaries agreed
- [x] Contract authority, one-decision timing and historical/current separation explicit
- [x] Existing strict runtime and schema compatibility preserved in slice A
- [x] Document limits, local debugging and initial retention addressed
- [x] Slice A offline verification and final diff reviewed
- [ ] Downstream receipts, authenticated acquisition and Python verifier implemented
- [ ] Separate producer integration and live acceptance planned/authorized

## 18. Handoff

Implement only the explicitly selected slice above. Slice A uses
`issue-11-v1alpha3-admission-contract` and references #11 in commits and its PR,
with `[ai]` prefixes. Preserve unrelated checkouts and worktrees. Do not execute
or copy the TypeScript evaluator into environments: share reviewed contracts and
fixtures. Complete repository checks and stop with that slice's reviewable PR and
offline verification report. Do not proceed automatically to later slices.

Slice A offline verification (September 14, 2026): `npm ci --ignore-scripts`
completed; `npm run ci` passed generated-source checks and all 108 tests (95 action
tests including eight new decision pairs, plus 13 local-tool tests).
`git diff --check` passed. Node v24.14.0 / npm 11.9.0. The eight pairs also passed
with the focused local command in the fixture README. No production source,
generated JavaScript, schemas, existing JSON vectors or dependencies changed.
No live signature, GitHub acquisition, registry, admission or AWS behavior was
tested; those integrations are outside slice A. The final diff review also removed
the old manual-pin/fresh-evidence requirement from the exemption PR template.

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
