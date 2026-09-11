# Governed vulnerability exemptions

This is the central approval location, not a scanner ignore directory. **There
are no active approvals in this foundation PR.** Hosted and local execution
still use the existing strict CRITICAL gate until the integration rollout.

After that rollout, records live at `<component>/<EX-ID>.json`, for one of:
`recommendation-mcp`, `reservation-mcp`, `recommendation-service`,
`reservation-agent`, or `reservation-web`. The legacy reservation-service pilot
is not enrolled by this change. One record covers one component, CVE, exact
versioned PURL (including qualifiers), package name/version, and linux/amd64.
No wildcards, cross-component inheritance, or source-commit locks.

TODO ([component onboarding #10](https://github.com/movie-reservation-platform-lab/movie-platform-actions/issues/10)): replace duplicated component lists and identity
mappings with a reviewed, data-driven component registry. Cover the exemption
and evidence schemas, action profiles, and admission verifier together, with
consistency tests and a documented onboarding procedure. Preserve explicit
allowlisting and pinned trust identities; do not accept arbitrary caller-supplied
repositories or discover trusted components from exemption requests. The current
five-component list remains unchanged until that follow-up is designed. Evaluate
service-owned metadata versus a central onboarding/meta repository as the source
of truth, including how new entries are reviewed before becoming trusted.

Use the [exemption PR template](../.github/PULL_REQUEST_TEMPLATE/security-exemption.md)
and the `security-exemption` label. GitHub's PR creation URL can select it with
`?template=security-exemption.md`; apply the label manually. Several explicit
records can share analysis and one PR. The label/template are not approval.

## Request and approve

1. Capture the complete production-image report. Copy the exact package name,
   installed version, and `PkgIdentifier.PURL`; retain encoded characters and
   qualifiers. Do not infer approval from package name alone.
2. Create a record using the [contract](../docs/vulnerability-exemption-contract.md)
   and the synthetic examples under
   [test/fixtures/vulnerability-policy](../test/fixtures/vulnerability-policy/).
   Those examples are not real CVEs or approvals and must never be copied into
   active policy unchanged.
3. Explain the primary advisory/analysis, scope, accountable owner, and rationale.
   Choose `not-affected` (maximum 90 days) or `risk-accepted` (maximum 30 days).
   For accepted risk, describe remediation/review actions in the VEX action
   statement; do not claim the vulnerability is absent.
4. Open the central PR first, then put its URL in `approval.reference`. Set the
   final approval time and expiry when the maintainer makes the decision. The
   VEX author/time must match that decision; newly scanning an image must not
   refresh either timestamp.
5. Run `npm run ci`. The designated maintainer currently is **@patex1987**, who
   may also author the request. Record their explicit decision in the PR before
   merging. This lab currently has one member, so this is not independent
   security-team review. A self-declared `approval.by` field is not authentication.
6. Once integration is available, adopt the reviewed full commit SHA in the
   producer and independently in admission. Enable approved exemptions explicitly.
   Obtain fresh canonical evidence; a policy PR alone does not admit an image.

When collaborators join, review CODEOWNERS, merge permissions and required reviews
before treating additional contributors as approval authorities. CODEOWNERS without
enforcement does not guarantee approval. Do not introduce a separate service merely
to model roles in this lab.

## Renew, remove, or withdraw

- Renew through another reviewed PR. Keep the ID, increment the VEX version,
  update the review rationale/time/reference and expiry. The lifetime limit
  starts from the new approval time. No automatic renewal or grace period.
- A code change does not cancel an otherwise in-scope approval. A different CVE,
  component, versioned PURL, package identity, or platform is not covered.
- Expired approval cannot unblock CRITICAL. An unused expired record produces a
  cleanup warning, not a new gate on an already-fixed image. Remove obsolete
  records through a PR; Git history preserves the audit trail.
- Every use is visible. The final seven days add an expiry warning in scan output;
  no scan means no reminder. There is no scheduled notification service.
- For emergency withdrawal, pause affected publication/admission, remove the record
  through review, update producer and admission policy pins, verify rejection of
  earlier evidence relying on it, then resume. Deletion on main is not instantaneous
  revocation for old pins. Do not restore a revoked policy pin during rollback.

Expiry does not terminate already-running services. Runtime scanning/incident
response remains separate; its existence is not assumed by this feature.

Publication and local integration are PR3; independent admission support is PR2.
See the [reviewed plan](../docs/plans/governed-vex-exemptions.md) for dependencies.
