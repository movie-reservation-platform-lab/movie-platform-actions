# Runtime integration review and new-joiner refactor

Review baseline: PR #13, commit `e4ea8a669e9dc8d48a61f98c907d5ba7efac754b`.
Scope: the runtime integration introduced in that PR. Preserve the reviewed
contract, strict legacy defaults, one current policy acquisition/evaluation,
complete findings, artifact membership and all producer/environment boundaries.

## Review instructions

The user requested the four definitions under `.codex/agents/`. Reviewers read
those exact TOML files and followed their `developer_instructions`. Their configured
`gpt-5.4` backend was unavailable on this account, so the available inherited agent
model ran the same instructions. The canonical tracked definitions are under
[`.ai/agents/`](../../.ai/agents/).

- Security: no material baseline or refactor findings; changed verification helpers
  preserve authority, bounds and rejection behavior.
- System design: no material baseline or refactor findings; diagnostics remain before
  blocker rejection and unchanged-member verification remains before candidate writing.
- Readability/maintainability: findings R1–R4 below are resolved on re-review; no
  additional actionable findings. The reading guide accurately describes the code.
- Performance/reliability: no material baseline findings. Cold database downloads
  in two disposable scanner containers and cleanup on hosted workflow cancellation
  remain unmeasured acceptance considerations, not reasons to add caching or alter
  the bounded process design in this refactor.

## Collected findings and changes

| ID | Finding at baseline | Why it matters | Refactor / verification |
| --- | --- | --- | --- |
| R1 (P2) | `test/runtime-v3.test.mjs` combines rejection scenarios through conditional mutations and accepts any rejection. | An unrelated exception can satisfy a test for the wrong security boundary. | Give each scenario a named setup and expected rejection reason, retaining no-candidate assertions. |
| R2 (P3) | Local `evaluateReport` mixes regex indices, JSON structure checks, subject/count checks and exit-code invariants. | A new maintainer cannot easily distinguish a successful approved-CRITICAL result from a malformed child result. | Parse named output fields; validate approved diagnostic structure, identity, count partition and result in distinct steps. |
| R3 (P3) | `acquirePolicy` embeds API requests, tree traversal, blob verification and approval validation under generic names. | The difference between authoritative emptiness and failed acquisition is hard to see. | Extract named verification phases and explain missing-component versus missing-root behavior. |
| R4 (P3) | `parseJson` has a custom traversal called `space`/`string`/`value` without explaining what the final parser still checks. | A maintainer could mistake duplicate/depth checking for the full JSON grammar implementation. | Name the traversal operations and document UTF-8, structure, grammar and finite-number checks separately. |
| R5 (new-joiner review) | The v3 evidence writer compresses publication context, captured files, decision, repeated reads and document construction. | The one-decision sequence and reason for rereading the files are difficult to trace. | Use a named publication context and named captured-member fields; give each phase a focused helper. |
| R6 (new-joiner review) | Summary/scanner variables such as `e`, `length`, `config` and `run` obscure what is counted or which credential/process boundary is involved. | Reviewers must reconstruct units and ownership from surrounding code. | Use explicit evaluation/byte-count/registry-directory/command-runner names and explain exported helpers. |

These clarity findings do not justify changing policy semantics or introducing a
new architecture layer. Keep adapters small, generated JavaScript synchronized,
and existing runtime interfaces intact. Reuse behavior tests; add or strengthen
coverage only where the findings expose a missing assertion or runtime defect.

## Completed verification

All R1–R6 changes are implemented. All four reviewers rechecked the refactor and
reported no additional actionable findings. Performance review confirmed that
helper extraction adds no repeated scans, requests or unbounded work.

- `npm run ci`: **185 offline tests passed** (153 actions, 32 local), including
  generated-source checks. Eleven new local output tests cover the approved/strict
  distinction and specific malformed or inconsistent diagnostic relationships.
- The actual writer generated four synthetic packages: not affected, accepted risk,
  clean, and unused expired policy. The independent environments reader at
  `dc04e29a8de19ad2c79e1473ea54fbaaa2cec610` accepted all four. Every package member
  matches the pre-refactor output except the candidate generation timestamp.
- `git diff --check` passed. TypeScript and regenerated JavaScript are included in
  the same `[ai]` refactor commit on PR #13.

This establishes offline behavior and package compatibility; it does not measure
live scanning, signing, cancellation or admission acceptance.

Consumer pins, real exemption records, sibling worktrees, merges, publication,
admission and AWS state remain outside this refactor.

## Reading guide for a new teammate

For a hosted run, start at `actions/container-evidence/action.yml`: version selection
keeps legacy behavior separate, verifies provenance, scans the exact image, writes
the candidate, then signs/uploads four explicit files.

Follow `generateV3Evidence` in `candidate-v3.mts`. Its main sequence reads as:
validate publication context → capture original files → acquire/evaluate once →
retain diagnostics → reject blockers → recheck file stability → build/write candidate.
`CapturedMember` keeps each member's original bytes, path and size limit together.
The second read detects changes while policy acquisition was running; it is not a
second scan or approval check.

`evaluateApprovedReport` in `approved-evaluation.mts` gets a `PolicySnapshot`, samples
the decision time after acquisition, and calls the existing pure evaluator. The
result's `ApprovedDecision` includes the policy revision and original report hash.
The name means the approved-policy evaluation mode; its result can still be `failed`.

In `policy-source.mts`, `githubPolicyReader` owns authentication, HTTPS and response
bounds. `acquirePolicy` owns the one-revision acquisition sequence. `readCompleteTree`,
`findDirectorySha`, `decodeVerifiedBlob` and `readVerifiedApprovalRecord` express the
individual checks. A complete tree can establish that a component has no approvals;
a missing central root or failed request cannot. Git blob SHA-1 proves byte identity
within that acquisition; canonical record SHA-256 is the separate contract identity.

`runtime-files.mts` handles bounded regular-file reads, exclusive JSON writes and
safe diagnostics. Its JSON traversal prevents duplicate keys and excessive nesting;
`JSON.parse` still validates the grammar and builds values. `RuntimeError` marks an
author-controlled message safe to show, so raw filesystem/process errors must not
be wrapped in that class.

For local/PR checks, follow `scan.mts` → the shared version-dispatch evaluator →
`runLocalEvaluation`. `evaluator-output.mts` explains the return protocol using
named fields and separate checks for subject, counts, CRITICAL coverage and exit
status. A successful v3 scan may have raw CRITICALs, but every one must be accounted
for as approved. The retained local JSON does not authorize publication or admission.
