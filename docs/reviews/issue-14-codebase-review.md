# Issue #14: codebase review and corrections

Reviewed 2026-09-15, baseline bb40579, on issue-14-authenticated-prepare.
The engineer requested all repository review agents, an assessment from a new
joiner's perspective, and fixes for concrete findings.

## Review execution

The definitions are in repository-relative .codex/agents, generated from .ai/agents.
The literal /.codex/agents directory was absent. Attempts to use the definitions'
gpt-5.4 model failed because that model is unsupported for this account. All four
roles then ran with the available inherited model and the same read-only role
instructions: security-practices, performance-scalability,
readability-maintainability, and system-design-scalability.

Reviews covered authored actions, local tools, tests, contracts and caller docs.
Post-fix security/performance/readability passes inspect the changed code. No
reviewer performed live GitHub/registry/AWS acceptance or changed external state.

## Findings and fixes

| Finding | Impact | Correction and evidence |
| --- | --- | --- |
| Legacy report reads were unbounded and accepted special files. | A FIFO reproduced a hung evaluator; large input could exhaust memory before the later gate. | Evaluator/writer use existing descriptor-based readDocument with a 64 MiB cap and regular-file/link checks. New legacy-safety tests cover FIFO, directory, symlink and oversized sparse input with bounded subprocess execution. |
| Legacy parser and validation errors could reveal input data. | Node JSON errors include source excerpts; field-validation messages echoed untrusted values. | Controlled RuntimeError diagnostics replace arbitrary errors and input interpolation. Malformed-report, environment, report-field and filesystem sentinels are checked in both entrypoints. |
| Nonzero Docker cleanup status was ignored. | Failed container removal could omit recovery guidance. | Cleanup checks both spawn error and exit status. A fake Docker regression verifies named cleanup, original scan failure, retained report and safe warning. |
| Provenance test checked flag presence, not values. | Wrong SHA/ref/issuer could pass the regression test. | Assert the exact gh argument vector, documenting repository, image, signer, source SHA/ref, issuer and hosted-runner restriction. |
| Composite test could pass when steps were missing. | Empty references satisfied every(); a missing attestation index could still precede upload. | Require nonempty action references and presence of both named steps before asserting immutable pins/order. |
| Build instructions hid the Git-index comparison. | A new maintainer could regenerate correctly and still encounter unexplained CI failure. | README explains build, review, stage generated changes, then run CI. The generated gate stays unchanged. |
| Local exit documentation assumed all CRITICALs always block. | V3 success with reviewed exact approvals appeared inconsistent with the documented exit code. | Local README/runbook distinguish strict default from governed v3 behavior. |
| V3 status/header and profile filename wording were stale or ambiguous. | Readers could think v3 was unavailable or the legacy filename applied to every version. | Correct schema description only, writer module comment, and profile's legacy-document comment; validation semantics and identities are unchanged. |
| No concise entrypoint/test reading guide. | Understanding shared v2/v3/local modules required searching many files. | README maps responsibilities to source modules and behavior tests. No repository-wide renaming or new class hierarchy. |

The known prepare defect is also implemented under #14: a dedicated authenticated
HTTPS adapter, required token input, fixed authority/ref, single 30-second deadline,
4096-byte response limit, exact source comparison and fixed diagnostics. The new
prepare suite exercises the actual adapter with a lifecycle double and runs the
generated executable through an isolated test preload. Production has no test
endpoint, credentials fallback or configurable timeout.

## New-joiner assessment

The core policy names already communicate intent: publicationContext,
readTrivyFindings and validateApprovedDiagnostic are more useful than generic
manager/service names. Pure policy and narrow adapters make security decisions
traceable. Classes are not needed for every operation; a small error type is useful
where it carries a closed diagnostic code across the HTTP boundary.

The main difficulties were version distinctions, finding the correct entrypoint,
and tests that claimed a stronger guarantee than they asserted. The reading guide,
corrected version wording and exact assertions address those points. New tests use
named failure scenarios and explicit expected outcomes, and explain temporary
files/fake HTTP or Docker behavior. Existing broad fixtures were retained where
rewriting them would add review cost without improving a concrete guarantee.

## Verification and review boundaries

Focused verification completed during implementation:

- 63 prepare tests passed, including header/body timeouts using fake timers.
- 32 legacy safety tests passed, including prompt FIFO rejection.
- 33 local-tool tests passed, including unsuccessful cleanup.
- 24 existing container-evidence tests passed after stronger assertions and moving
  prepare coverage to its dedicated suite.
- Runtime-v3 regressions passed in the legacy-fix verification.

Final combined verification passed: npm run ci completed with **247 action tests
and 33 local-tool tests (280 total)**, including source compilation and the
generated-file check. Working-tree and staged diff whitespace checks passed.
Post-fix security, performance and readability reviews found no remaining
actionable issue in the changed code. The performance reviewer independently
ran the 95 prepare/legacy safety cases successfully.

The HTTP double tests adapter byte accounting and lifecycle behavior; it does
not reproduce Node's HTTP framing parser or a real TLS connection. No live
private-resource access was tested, as agreed in the Q&A.

Keep review concerns grouped: authenticated prepare; legacy file/diagnostic
hardening; scanner cleanup; test/documentation clarity. New shared authentication
or architecture work remains in [#15](https://github.com/movie-reservation-platform-lab/movie-platform-actions/issues/15),
[#16](https://github.com/movie-reservation-platform-lab/movie-platform-actions/issues/16),
[#3](https://github.com/movie-reservation-platform-lab/movie-platform-actions/issues/3)
and [#10](https://github.com/movie-reservation-platform-lab/movie-platform-actions/issues/10).
