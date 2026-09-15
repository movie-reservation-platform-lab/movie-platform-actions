# Implementation Plan: Authenticated Prepare Main Resolution

Issue: [#14](https://github.com/movie-reservation-platform-lab/movie-platform-actions/issues/14)
Branch: issue-14-authenticated-prepare
Planning completed: 2026-09-15. All eight discussion topics are settled.
Status: Implemented locally and verified; ready for human review.
After the Q&A, the engineer explicitly requested the configured agents, a
new-joiner review, and fixes for the collected findings. That request authorizes
implementation and the concrete review corrections recorded below.

## 1. Summary

Replace prepare's anonymous Git lookup with one authenticated HTTPS request for
the reviewed component repository's main ref. Use a small dedicated adapter,
validate the complete response, and retain the exact comparison with GITHUB_SHA
before writing outputs. Deliver one focused implementation PR with source,
generated JavaScript, tests, caller documentation, and a short authentication audit.

## 2. Goals

- Support canonical private/internal repositories on GitHub.com using the
  caller's explicit token and minimum contents: read permission.
- Keep closed repository/ref selection, exact revision matching, and failure
  before outputs on all rejected lookups.
- Bound resource use and expose useful diagnostics without secret or remote data.
- Prepare a reviewable rollout, starting with recommendation-mcp.
- Identify other public-access assumptions without expanding this fix.

## 3. Non-goals

- GitHub Enterprise Server, caller-selected hosts/repos/refs, anonymous fallback,
  retries, caching, dependency additions, or a shared HTTP transport refactor.
- Changes to approval retrieval, evidence schemas/layout, vulnerability gates,
  profile identities, signer checks, hosted-runner enforcement, or publication
  permissions outside the new prepare input.
- Structured event contracts, injectable telemetry sinks, or exporters.
- Third-party action internals, transitive download audits, or guarantees that
  future organization policies and credentials are already correct.
- Live publication, workflow dispatch, admission, deployment, merging, or
  GitHub/AWS environment changes.

## 4. Current State

Inspected on main baseline bb40579 before creating the issue branch:

- actions/container-evidence/src/prepare.mts calls publicationContext, then
  git ls-remote with a 30-second timeout and 4096-byte maxBuffer. It compares one
  exact ref line and appends image_ref, tag, and artifact to GITHUB_OUTPUT.
- actions/prepare-container-candidate/action.yml accepts component only.
  Its public outputs are image_ref and tag; the script's artifact output is
  not separately declared in this action's metadata.
- actions/container-evidence/src/profile.mts owns pure closed profiles and
  checks repository, push/main, GitHub.com, job ID, SHA and run identifiers.
  It does not currently validate GITHUB_API_URL.
- actions/container-evidence/src/policy-source.mts contains authenticated HTTPS
  transport for central vulnerability approvals. Its endpoint allowlist and
  messages are specific to that operation; it remains unchanged.
- runtime-files.mts already provides strict UTF-8/duplicate-key-aware parseJson.
- test/container-evidence.test.mjs uses fake Git for prepare. The existing
  test/policy-source.test.mjs mocks node:https with syncBuiltinESMExports.
- docs/container-candidate-actions.md requires matching full-SHA pins for both
  actions and describes five consumers, caller permissions and rollback.
- ci_automations/check-generated.mjs compares generated files with the Git
  index and rejects untracked generated files. Build output must be staged
  before the full local CI command can pass after source changes.
- The environments sibling has local versioned event sinks and sanitized stderr
  renderers. These do not automatically collect this action's diagnostics.

## 5. Requirements and Assumptions

### Confirmed requirements and discussion decisions

| Topic | User decision |
| --- | --- |
| 1/8: HTTP reuse | A: dedicated prepare adapter; leave approval retrieval unchanged. |
| 2/8: Audit depth | B: authored code and action configuration only. |
| 3/8: Company target | A: private/internal repositories on GitHub.com. |
| 4/8: Retry policy | A: one attempt within a 30-second total request limit. |
| 5/8: Diagnostics | A: fixed messages per category; refined to stable codes plus prose, without event/sink infrastructure. |
| 6/8: Verification | A: offline tests and CI gate the PR; private access is checked during migration. |
| 7/8: Rollout | A: recommendation-mcp first, then separate PRs for the remaining consumers. |
| 8/8: PR split | A: one focused fix PR; audit follow-ups and consumer updates remain separate. |

### Subsequent review request

All four repository reviewer definitions were run. Their configured gpt-5.4
model was unavailable for this account, so the same role instructions ran with
the available inherited model. Findings and dispositions are recorded in
[the review report](../reviews/issue-14-codebase-review.md).

The engineer's request to fix findings expands local work to bounded legacy
report reads and safe diagnostics, scanner cleanup feedback, stronger existing
security assertions, and accurate onboarding/version documentation. These are
separate review concerns from the authenticated prepare change; they do not
implement the deferred authentication, telemetry or metadata issues.

The user's portability goal is practical company migration. Hardcoded organization
identities still need reviewed migration changes; adding authentication does not
make this codebase automatically portable to arbitrary organizations.

The token-visibility clarification is part of the documentation requirements:
committed YAML contains an expression, GitHub supplies the secret at runtime, and
log masking is additional protection rather than permission to print credentials.
Prepare needs contents: read, but receives all permissions of the caller job's
token. Scoping GH_TOKEN to a step does not reduce that token's authority.

### Engineering defaults selected for implementation

These fill in routine details without changing the decisions above:

- Node's built-in HTTPS client; no new runtime or development dependency.
- Fixed GitHub API version 2022-11-28, matching the existing reader and still
  supported according to official documentation checked during planning.
- 4096 actual response-body bytes, preserving the old lookup's byte budget.
  The exact-ref response for the fixed profiles is small; no repository/tree
  listings or pagination are needed.
- Token syntax follows the existing reader: 1–4096 visible ASCII characters,
  excluding whitespace/control characters. Do not assume a token prefix,
  decode it, trim it, or claim syntax proves authorization.
- Existing strict JSON parser is reused without modifying its implementation.

### Open questions

No remaining design questions block implementation. The final implementation SHA,
consumer PR identifiers and live adoption evidence are delivery-time facts.
New scope or materially different implementation constraints require updating this
plan, not silently adding unrelated work.

## 6. Proposed Design

### Entrypoint and policy

Keep prepare.mts as the composition root:

1. Validate publicationContext using existing pure profile policy.
2. Require GITHUB_API_URL to equal https://api.github.com; retain the existing
   exact GITHUB_SERVER_URL check. The URL is a consistency check, never routing
   input. Validate GITHUB_OUTPUT is a nonempty value without control characters.
3. Resolve canonical main through the new canonical-main.mts adapter using
   the validated component and GH_TOKEN.
4. Compare the validated remote SHA with GITHUB_SHA using exact string equality.
5. Append the same output block only after all checks pass.

Do not modify profile.mts merely to impose prepare-only API checks on unrelated
entrypoints. Preserve the existing output append contract; broad filesystem
refactoring is outside this fix. An I/O failure must report a controlled error
and nonzero exit; appending is not claimed to be crash-atomic.

### Dedicated adapter

Add actions/container-evidence/src/canonical-main.mts with a narrow
resolveCanonicalMain(component, token) operation returning Promise<string>.
Resolve the repository internally with profileFor; accept no repository string,
ref, endpoint, headers, or transport options from action inputs/environment.

Use a small pure response validator within this module. It accepts unknown,
checks a single non-null non-array object, exact ref refs/heads/main, an object
target of type commit, and a lowercase 40-hex SHA. Accept unrelated additive
GitHub fields within the byte bound, but never follow response URLs.

Use a closed lookup-error code type. Transport and parsing failures become
controlled lookup errors; raw exception objects/messages must not reach the
entrypoint's diagnostic renderer. No generic transport port is needed: the
existing built-in HTTP mocking convention gives deterministic adapter tests.

### HTTP boundary

Send exactly one GET to:

~~~
https://api.github.com/repos/<profile.repository>/git/ref/heads/main
~~~

Set hostname, port 443, path and method explicitly. Use TLS certificate validation,
agent: false, a fixed 16 KiB response-header cap, and these controlled headers:

- Authorization: Bearer <validated token>
- Accept: application/vnd.github+json
- User-Agent: movie-platform-actions
- X-GitHub-Api-Version: 2022-11-28

Do not read Git/gh credentials, GH_HOST, proxy configuration or API routing from
the environment; do not invoke a command-line client. Reject redirects and every
status other than 200. Discard error bodies without parsing or printing them.
Request uncompressed/default identity content; reject unexpected content encoding
instead of adding decompression.

Start one 30-second deadline when acquisition begins, covering DNS/connect/TLS,
headers and the entire response body. Do not reset the timer on activity. Count
actual streamed bytes before retaining chunks; reject above 4096 regardless of
Content-Length. Optionally reject an excessive declared length earlier, but it
must never replace actual-byte accounting.

Destroy the request/response on failure. Clear the timer and release buffers on
every terminal path. Handle request errors, response errors and incomplete/early
close, including failures after headers. Settle once; ignore late data/completion
after rejection. Verify completion before parsing, and check the elapsed deadline
before accepting a result. A socket inactivity timeout alone is insufficient.

Parse only a complete bounded body using parseJson, then validate the ref object.
Invalid UTF-8, duplicate keys, invalid JSON, arrays, absent/wrong fields, wrong
ref/type and malformed SHA all fail. No fallback, pagination, retry or stale cache.

### Diagnostic presentation

Render a single fixed-code message on stderr with prefix
[prepare-container-candidate]. Never render a caught error's arbitrary message,
cause, stack, response text or filesystem path.

| Code | Fixed message / troubleshooting direction |
| --- | --- |
| invalid-publication-context | Publication context is invalid; check the canonical repository, push/main guard, job and GitHub URLs. |
| invalid-github-token | GitHub token is missing or invalid; pass github.token through the required input. |
| canonical-main-unavailable | Canonical main lookup failed; check repository read access, main branch availability and GitHub connectivity/status. |
| canonical-main-timeout | GitHub lookup exceeded 30 seconds; retry the workflow when connectivity is restored. |
| canonical-main-response-too-large | GitHub response exceeded 4096 bytes; investigate the response contract without logging its body. |
| canonical-main-invalid-response | GitHub returned an invalid canonical main reference; investigate the API contract. |
| stale-main-revision | Run revision is no longer canonical main; use a run for the current main commit. |
| prepare-output-failed | Unable to write prepare outputs; check the runner output-file setup. |
| prepare-failed | Container candidate preparation failed; inspect the reviewed action implementation and runner setup. |

Non-200 responses and raw transport errors share canonical-main-unavailable;
do not falsely diagnose every 403 as bad credentials or every 404 as a missing repo.
Map missing/invalid output setup to prepare-output-failed before any request.
An unknown thrown error falls back to prepare-failed.

Stable codes are a lightweight troubleshooting convention. Future operational
events already belong to [issue #3](https://github.com/movie-reservation-platform-lab/movie-platform-actions/issues/3).

## 7. Alternatives Considered

### A: Dedicated Node HTTPS adapter — selected

- Pros: small affected scope, explicit request lifecycle/byte bounds, existing
  test conventions, no dependency or executable/config discovery.
- Cons: limited duplication with approval transport.
- Decision: matches Q1 and avoids changing another security-sensitive path.

### B: Shared HTTP extraction — deferred

- Pros: consolidates transport mechanics.
- Cons: changes approval retrieval and expands regression review.
- Decision: not a prerequisite. The subsequent user-requested comparison of a
  CLI wrapper, JS/TS client and shared built-in transport is tracked in
  [#17](https://github.com/movie-reservation-platform-lab/movie-platform-actions/issues/17).

### C: Authenticated gh api subprocess — not selected

- Pros: runner-provided CLI already exists elsewhere in the workflow.
- Cons: adds executable/config/environment behavior and output/status parsing
  to a lookup whose complete HTTP lifecycle needs explicit bounds.
- Decision: use the existing repository's direct-HTTPS pattern.

## 8. API / Interface Changes

Add required github-token to actions/prepare-container-candidate/action.yml.
Describe repository read access and non-retention. Set GH_TOKEN only in the
prepare step's env from inputs.github-token; never interpolate it into shell text.

Caller examples use:

~~~yaml
permissions:
  contents: read

steps:
  - id: candidate
    uses: movie-reservation-platform-lab/movie-platform-actions/actions/prepare-container-candidate@<reviewed-full-commit>
    with:
      component: recommendation-mcp
      github-token: ${{ github.token }}
~~~

This illustrates prepare's minimum only. The full publishing job retains its
separately justified package/attestation/OIDC permissions. Keep both shared-action
pins identical. Existing callers pinned to old commits continue their old behavior;
updating the pin without adding the required token intentionally fails closed.

## 9. Data Model / Persistence Changes

None. Evidence schemas, profile identities, file membership and output values
remain unchanged. Add no token file, response artifact, telemetry event schema,
persistent cache or new failure output.

## 10. Security, Privacy, and Abuse Considerations

- Trust originates in reviewed closed profiles, not caller repository/ref inputs
  or returned URLs. Validate context before making any authenticated request.
- Credentials travel only through the prepare environment and fixed HTTPS
  authorization header; never through Git URLs, argv, outputs or artifacts.
- Tokens remain available to executing job code. Reviewed full-SHA pins and
  trusted caller workflows remain necessary; step scoping is not a sandbox.
- Validate syntax locally and access through the authenticated HTTP result;
  require a token even when GitHub could serve the resource publicly.
- Retain all downstream provenance/hosted-runner/gate checks. A lookup is a
  point-in-time main check, not a lock preventing main from advancing afterward.
- Sanitized static messages prevent remote text or token values becoming log
  content or workflow commands. Offline tests exercise sentinel leakage.
- See the separate audit for cross-repository private access and public tooling
  dependencies. This fix cannot prove complete company portability.

## 11. Performance, Scalability, and Reliability Considerations

One API call, at most 4096 retained body bytes and a 30-second acquisition budget.
No retry amplification, background process, cache or telemetry delivery. Use
bounded headers and destroy connections on timeout/overflow/interruption.
Tests advance fake timers; CI must not spend 30 seconds per timeout case.
A transient failure can block publication until the engineer reruns the workflow,
as accepted in Q4. Authentication does not remove GitHub rate limits.

## 12. Implementation Steps

1. **Add the lookup adapter and its tests.**
   - Files: src/canonical-main.mts under actions/container-evidence and
     test/prepare.test.mjs.
   - Implement fixed request parameters, pure ref validation, controlled lookup
     errors, strict JSON decoding, complete-body limits and lifecycle cleanup.
   - Verify real adapter behavior using mocked node:https, not only stubbed SHAs.

2. **Wire prepare and the public input.**
   - Files: src/prepare.mts and actions/prepare-container-candidate/action.yml.
   - Add GH_TOKEN mapping, environment checks, await lookup, exact SHA comparison,
     controlled stderr rendering, and successful-only output append.
   - Keep the current component/policy/output contract.
   - Verify the executable with synthetic token/response/error sentinels.

3. **Replace the old prepare fixture and cover metadata.**
   - Files: test/container-evidence.test.mjs, test/prepare.test.mjs, and a small
     test/support/prepare-http-fixture.mjs if needed for subprocess tests.
   - Remove/replace the fake-Git prepare case; preserve unrelated tests.
   - Use an isolated Node --import test preload that replaces HTTPS request and
     synchronizes built-in ESM exports before loading the real generated entrypoint.
     No test mode, endpoint override or timeout input enters production code.
   - Keep subprocess environment explicit: synthetic GH_TOKEN, canonical API URL,
     temporary output path, no ambient credentials or inherited NODE_OPTIONS.
   - Assert required input metadata and process-only token mapping.

4. **Update caller documentation and audit follow-ups.**
   - Files: README.md, docs/container-candidate-actions.md,
     docs/reviews/github-authentication-portability.md, this plan as necessary.
   - Document new input/minimum permission, GitHub.com scope, error codes,
     limits/no retries, safe troubleshooting, matching pins and rollback.
   - Retain git/gh obligations needed by other workflow steps; do not remove
     caller tools merely because prepare stops using Git.
   - Verify findings against authored code/configuration and maintain links to
     the already opened follow-ups: #15 (private central-policy access) and #16
     (scanner authentication/downloads). Do not open duplicates or implement
     those fixes within #14.

5. **Regenerate and verify.**
   - Run npm run build and include src/prepare plus src/canonical-main and their
     generated lib/prepare.mjs and lib/canonical-main.mjs counterparts.
   - Run focused tests, then stage only intended generated/source/test/doc changes
     so check:generated can compare the build with the index.
   - Run npm run ci and git diff --check. Inspect the final diff for secret
     leakage, unrelated changes and accidental changes to approval transport.

6. **Prepare one reviewable fix PR.**
   - Link #14, explain the new required input and exact successful-output guard,
     report actual validation and its offline limitation, and link audit issues.
   - Suggested review units: implementation/tests/generated output; caller docs
     and audit. Keep generated output visibly paired with its source.
   - Do not merge or execute consumer publication. Consumer rollout follows §14.

## 13. Testing Strategy

Use Node's built-in runner against checked-in generated JavaScript. Reuse
mock.method(https, "request") plus syncBuiltinESMExports and restore mocks in
cleanup; avoid concurrent tests sharing these process-global mocks. Use fake
timers for stalled headers and stalled/slow body cases. The mock must exercise
destroy, complete/incomplete response state and late-event behavior faithfully.

| Boundary | Focused cases and expected evidence |
| --- | --- |
| Success | All five components map to exact canonical URLs; matching valid response writes exactly the existing outputs. |
| Context | Wrong repository/ref/event/job/server/API URL, malformed source SHA/run IDs, unknown component fail before network/output. |
| Token | Missing, empty, whitespace/control/newline/non-ASCII and over-limit tokens fail before network; valid syntax alone cannot bypass a denied API response. |
| Request | Fixed HTTPS host/port/path/method/headers, certificate validation, bounded headers, one attempt, no redirect/fallback or environment-selected destination. |
| HTTP failures | 401, 403, 404, 429, 5xx, redirects and unexpected status fail with safe messages; error bodies are not accepted. |
| Response | Invalid UTF-8/JSON, duplicate keys, empty body, primitive/null/array, missing/wrong ref/object/type/SHA fail. |
| Bounds | Exactly 4096 valid bytes can pass; 4097 fails, including chunked data and absent/misleading Content-Length. |
| Lifetime | No headers, body stall/drip beyond total deadline, connection error, early close/incomplete body; request destroyed and no later output/retry. |
| Revision | Valid but different SHA fails; no case normalization, prefix comparison or matching-ref array acceptance. |
| Diagnostics/output | Stable codes and nonzero exits; token/header/body/transport/path sentinels absent from logs and outputs; existing output contents unchanged on rejected lookup; output write failure sanitized. |
| Metadata/regression | Required input, step env mapping, unchanged public outputs and pinned third-party actions; existing evidence suites remain green. |

No ordinary test calls GitHub, registries, OIDC or AWS. Synthetic credentials only.
No live private-repository smoke gate was requested. Actual runner/network/TLS
integration and target-organization access are rollout/migration checks.

Verification commands:

~~~sh
npm ci --ignore-scripts
npm run build
node --test test/prepare.test.mjs test/container-evidence.test.mjs
# Stage the reviewed generated changes before check:generated compares the index.
npm run ci
git diff --check
~~~

Install only when dependencies are not already available. Do not rerun broad tests
without new changes or an unresolved concern after they pass.

## 14. Rollout / Migration Plan

1. Review the single shared-action fix PR, including its required input change.
2. After the engineer-controlled merge/release, obtain the exact reviewed final
   full commit SHA. Do not use main, a mutable tag or an abandoned PR head.
3. Prepare a separate small recommendation-mcp consumer PR: both action pins
   use that SHA, prepare receives github.token, and contents: read is present.
4. Validate the first adoption during the separately authorized consumer rollout.
   Confirm canonical prepare succeeds and the normal downstream gates retain
   their behavior. Do not bypass unrelated scan/admission failures to call it green.
5. Update reservation-agent, recommendation-service, reservation-mcp and
   reservation-web ECS in separate small consumer PRs after the pilot validation.
6. Revert both pins and the new prepare input together to roll back a consumer.
   The old implementation restores its old public-access limitations; rollback
   is not a solution for private access.

Current repository rollout and future company migration are distinct. For the
company migration, review closed organization identities, central-policy token
access and private action sharing settings. Offline success is not evidence that
these settings are configured. No feature flag or anonymous compatibility path.

## 15. Risks and Mitigations

| Risk | Impact | Likelihood | Mitigation |
| --- | --- | --- | --- |
| Consumer updates pin but omits token | Prepare blocks publication | Plausible | Same-PR pin/input changes, required runtime check, pilot first. |
| Token leaks through failures | Credential exposure | Plausible without controls | Fixed destination, static diagnostics, sentinel tests, no retained response. |
| Timer only covers idle socket | Slow responses hang prepare | Plausible implementation bug | Total deadline, destroy/cleanup, stalled and drip-body tests. |
| Main advances after lookup | Guard cannot lock publication to latest forever | Inherent | Preserve point-in-time semantics; no stronger claim. |
| Private central policy lacks access | V3 evidence generation blocks | Expected with only producer token | Separate scoped follow-up; no policy fallback. |
| Future organization/tooling restrictions | Migration or downloads fail | Unknown | Bounded audit, explicit gaps and actionable diagnostics. |
| Single PR grows beyond agreed scope | Review becomes difficult | Controllable | Two production source targets, no shared transport/sinks, separate follow-up issues. |

## 16. Done Criteria

- Required github-token input is wired only to the prepare process.
- One authenticated fixed-endpoint lookup is validated and bounded; rejected
  lookups write no outputs, matching revision preserves the existing values.
- Fixed diagnostic codes/messages and caller troubleshooting docs are complete.
- Focused offline tests and full npm run ci pass; generated JavaScript matches;
  git diff --check passes.
- Audit separates facts from unverified third-party behavior and links distinct
  follow-up issues without implementing them.
- One fix PR is ready for human review; pilot/rollback instructions are concrete.
- No unrelated source, approval, schema, environment or live workflow changes.

Use the review report for actual implementation verification results.

## 17. Review Checklist

- [x] Requirements and all eight user decisions are explicit.
- [x] Non-goals and mutation limits are explicit.
- [x] Existing source, metadata, docs and test conventions were inspected.
- [x] Alternatives and affected code scope were considered.
- [x] Token, response, transport and output boundaries are specified.
- [x] Runtime bounds, cleanup and failure behavior are specified.
- [x] Offline testing strategy and its live-access limits are explicit.
- [x] Pilot, full-SHA adoption and rollback are defined.
- [x] Implementation steps name files and verification.
- [x] Implementation diff reviewed; npm run ci passed with 247 action and
  33 local-tool tests, generated-file checks passed, and diff hygiene passed.
- [x] Follow-up issues #15 and #16 are opened and linked in the audit.

Guidance used: principal-engineer-planner, programming-kb, clean-architecture,
typescript and testing. Clean-architecture kept transport small and profile
policy pure; TypeScript/testing guidance requires runtime validation and tests
of the generated executable rather than types or fixtures alone.

Used KB notes (under /home/patex1987/Documents/programming_kb):
concepts/Clean Architecture.md; concepts/Dependency Inversion and Dependency
Injection.md; concepts/API Compatibility.md.

Official references checked during planning:

- [Exact Git ref endpoint and read permission](https://docs.github.com/en/rest/git/refs?apiVersion=2022-11-28#get-a-reference).
- [Supported API versions](https://docs.github.com/en/rest/about-the-rest-api/api-versions).
- [Built-in token scope/lifetime](https://docs.github.com/en/actions/concepts/security/github_token).
- [Token usage and permissions](https://docs.github.com/en/actions/tutorials/authenticate-with-github_token).
- [Secret masking limitations](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#github-context).
- [Node HTTP request timeout behavior](https://nodejs.org/docs/latest-v24.x/api/http.html#httprequestoptions-callback).
- [Node mock timers](https://nodejs.org/docs/latest-v24.x/api/test.html#class-mocktimers).

## 18. Handoff Prompt for Implementation Agent

~~~text
Continue docs/plans/authenticated-prepare-main-resolution.md for issue #14
on issue-14-authenticated-prepare. Implementation was authorized by the subsequent
request to run reviewers and fix their findings; do not repeat that approval gate.

Deliver one focused fix PR's changes: dedicated canonical-main HTTPS adapter,
required prepare github-token input, runtime checks, one 30-second attempt,
4096-byte body bound, exact main/SHA comparison, fixed diagnostics, focused
offline tests, regenerated JavaScript, caller docs and audit follow-up issues.

Keep approval transport, closed identities, schemas, evidence layout, gates,
existing public outputs and third-party pins unchanged. No new dependencies,
generic transport refactor, telemetry sinks, retries or anonymous fallback.
Preserve unrelated work. Use apply_patch for edits and regenerate lib from src.

Primary targets:
actions/container-evidence/src/{prepare,canonical-main}.mts
actions/container-evidence/lib/{prepare,canonical-main}.mjs (generated)
actions/prepare-container-candidate/action.yml
test/prepare.test.mjs
test/container-evidence.test.mjs
test/support/prepare-http-fixture.mjs if needed
README.md
docs/container-candidate-actions.md
docs/reviews/github-authentication-portability.md

Use actual HTTPS adapter mocks and executable-level tests without live network
or ambient credentials. Build; run focused tests; stage reviewed generated
changes; run npm run ci and git diff --check. Report actual outcomes.

The audit follow-ups already exist: #15 covers private central-policy access;
#16 covers scanner authentication/downloads. Maintain their links; do not create
duplicates. Issue #3 owns future events; #10 owns component metadata work.
Prepare consumer rollout instructions with recommendation-mcp first and both
actions pinned to one reviewed full SHA. Do not merge, publish images, dispatch
workflows, admit/deploy artifacts or change GitHub/AWS environments.

If reality requires changing the agreed scope, update the plan and resolve that
difference before expanding implementation.
~~~
