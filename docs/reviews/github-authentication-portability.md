# GitHub authentication and company portability audit

Planning audit for issue #14, 2026-09-15, source baseline bb40579.

## Scope and confidence

The engineer selected repository-authored reusable-action code and action
configuration only. Third-party action/CLI/container internals, organization
settings and live private access were not tested. This is an inventory of
established wiring and migration gaps, not end-to-end portability certification.
The intended company target is private/internal repositories on GitHub.com.

## Findings

| Surface | Evidence from this repository | Disposition |
| --- | --- | --- |
| Prepare canonical main | src/prepare.mts invokes HTTPS git ls-remote with no explicit caller token; prepare action metadata has no token input. | Fix in #14 with an authenticated, fixed Git ref API request. |
| V3 approval retrieval | src/policy-source.mts uses an explicit token and fixed api.github.com host, but reads the central movie-platform-actions repository. Candidate/evaluation entrypoints supply GH_TOKEN. | Authenticated already; a private central repository needs access beyond the producer's built-in token. Follow-up 1. |
| Provenance verification | container-evidence/action.yml passes GH_TOKEN into verify.mts; the gh attestation verify child inherits it and uses the closed profile repository and signer identity. | Explicit token wiring exists. CLI-internal requests/configuration and registry authentication were not audited. |
| Attestation actions | Both pinned actions/attest-build-provenance invocations receive inputs.github-token explicitly. | No missing token wiring established here; upstream implementation and private-resource compatibility remain unverified. |
| Legacy v1alpha2 Trivy | Two pinned trivy-action steps have no explicit credential/token forwarding in this composite. The first performs setup; the second requests skip-setup-trivy. | Configuration gap to evaluate, not proof of anonymous internal calls; caller registry login may affect execution. Follow-up 2. |
| V3 Trivy scans | scan-v3.mts creates temporary GHCR-scoped auth from GH_TOKEN. The pinned scanner image is on Docker Hub; scanner arguments leave database-source defaults to the tool. | Explicit private-image credentials exist. Scanner image/database availability and authentication are separate concerns. Follow-up 2. |
| Artifact uploads | Pinned actions/upload-artifact invocations have no explicit github-token input in this composite. | Absence of that input alone is not a defect; runtime service-token behavior is outside this audit. |
| Organization identity | profile.mts fixes component repository/image names; policy-source.mts fixes the central repository; exemption validation and evidence contracts also encode identities. | Company migration requires coordinated reviewed identities, not arbitrary caller inputs. Coordinate with existing #10. |
| Private shared action loading | Caller docs reference this action by repository and full SHA. No source change can itself grant another repository permission to load a private action. | Document target-organization action-sharing configuration as a migration prerequisite; do not change settings in #14. |

Paths above are relative to actions/container-evidence/ unless another path is
given; generated lib files mirror the reviewed src implementation.

GitHub's built-in token is scoped to the workflow repository. Prepare checks
that this equals its canonical repository, while V3 central policy acquisition
crosses a repository boundary. A successful public-policy lookup does not prove
private cross-repository access. [Token scope](https://docs.github.com/en/actions/concepts/security/github_token)

GitHub separately controls whether other repositories may load an action from a
private repository, using a scoped download token. That action-loading mechanism
does not make the producer's GH_TOKEN a general credential for private policy
API calls. [Private action sharing](https://docs.github.com/en/actions/how-tos/reuse-automations/share-across-private-repositories)

## Follow-up 1: Private central-policy access

Tracking issue: [#15](https://github.com/movie-reservation-platform-lab/movie-platform-actions/issues/15).

Problem: the evidence action uses one github-token input for multiple operations,
including access to a central repository. The documented github.token example
cannot establish access to that central repository after it becomes private.

Design a separate policy-read credential boundary and consumer setup. Evaluate a
GitHub App installation token scoped to central-policy contents: read, preserving
the existing job token for registry/attestation operations. A personal access
token is an alternative to evaluate, not a newly approved credential choice.

Acceptance: document private repository access and lifecycle, keep fixed policy
identity and fail-closed behavior, add offline missing/denied/wrong-scope and
non-leakage cases, coordinate local/hosted callers, and prepare small migration
PRs. Do not create/install an App, add secrets, change settings or execute live
publication as part of issue creation. This does not block the same-repository
prepare fix. [GitHub App access](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/making-authenticated-api-requests-with-a-github-app-in-a-github-actions-workflow)

## Follow-up 2: Scanner credentials and public downloads

Tracking issue: [#16](https://github.com/movie-reservation-platform-lab/movie-platform-actions/issues/16).

Problem: legacy scanner configuration has no explicit credential forwarding,
while the V3 scanner authenticates the target GHCR image but also depends on a
public scanner image and tool-selected database downloads. The current bounded
audit cannot establish the authentication of those internal requests.

In this separate investigation, inspect the exact pinned scanner action/setup
paths and relevant tool behavior. Distinguish target-image credentials, scanner
installation, vulnerability databases and artifact-runtime credentials; identify
actual anonymous/rate-limited calls before proposing changes. Evaluate explicit
host-scoped credentials or reviewed token-based setup actions only where relevant.
Never pass a repository token indiscriminately to Docker Hub or database mirrors.

Acceptance: record exact pins/call paths and supported authentication, distinguish
confirmed defects from intentional public dependencies, define offline tests for
any wiring fix, preserve scan/gate behavior and immutable pins, and document
remaining organization-network assumptions. No live scan or infrastructure
changes are authorized by this issue.

## Existing follow-ups and limits

- [#17](https://github.com/movie-reservation-platform-lab/movie-platform-actions/issues/17)
  compares a common GitHub CLI wrapper with a JS/TS client and the existing
  built-in HTTP approach. It covers transport consistency and distribution;
  private-token access and specialized attestation verification remain explicit
  separate requirements.
- [#3](https://github.com/movie-reservation-platform-lab/movie-platform-actions/issues/3)
  owns optional versioned progress events/sinks. #14 emits fixed diagnostic
  codes and human messages only.
- [#10](https://github.com/movie-reservation-platform-lab/movie-platform-actions/issues/10)
  owns component metadata/onboarding coordination. The issue's platform-level
  catalog dependency should guide company identity migration.
- This audit did not inspect sibling producer workflow state, private sharing
  settings, npm dependencies, local-tool-only flows, or third-party internals.
  Follow-up 1 must account for local users of the same policy reader.
- Offline CI verifies the implementation; private access, package permissions,
  organization restrictions and live downloads are migration/rollout checks.
