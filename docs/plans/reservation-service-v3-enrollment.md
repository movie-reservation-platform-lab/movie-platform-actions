# Reservation-service v3 enrollment: slice A

Parent: [reservation-service #38](https://github.com/movie-reservation-platform-lab/movie-reservation-service/issues/38).
Base: `036531133bcefd454b5afc0eb55f8ba0328901ea` (authenticated prepare, PR #18).
Branch: `ai/reservation-service-v3-enrollment`.
Tracking: [actions #19](https://github.com/movie-reservation-platform-lab/movie-platform-actions/issues/19).
The engineer authorized implementation and PR creation. Merge, publication and
admission remain outside this slice. Reader dependency: environments #108.

## Scope and design

Enroll `reservation-service` in existing closed publication, policy and local-scan
profiles. Bind repository/image to `movie-reservation-platform-lab/movie-reservation-service`
and `ghcr.io/movie-reservation-platform-lab/movie-reservation-service`, workflow to
`.github/workflows/ci.yml`, and job ID/display name to `publish-candidate`.
Preserve canonical authenticated main push, source/run/attempt and exact digest
bindings. Reuse the current scanner and governed policy without active approvals.

The v3 schema currently inherits v2's five-component enum. Add a v3-specific
service choice and exact identity branch; do not modify v2 to make enrollment
easier. Runtime context and direct writer reject service v2 or omitted version.
The existing five components keep their v2 default and v3 behavior.

Add service to the exemption schema's component enum and exact VEX product
condition. This is reviewed enrollment, not an exemption approval. Temporary
allowlists remain tracked by [actions #10](https://github.com/movie-reservation-platform-lab/movie-platform-actions/issues/10)
and organization onboarding #11; a catalog refactor is not required here.

## Files and verification

- `actions/container-evidence/src/{profile,context,exemption-policy,write-candidate-evidence}.mts`
- `local-tools/container-security/src/scan.mts`
- V3 candidate and exemption schemas; unchanged historical v2 schema
- Generated JS from `npm run build`
- Prepare matrix, new service enrollment tests and local CLI v3 matrix
- Caller/local-scan/exemption documentation

Run `npm run ci` with generated changes included in the index (the repository's
drift check compares working output to the index). Ordinary tests use synthetic
reports, policies, HTTPS responses and Docker executables and remain offline.
Test exact identity mutations, omitted/v2 rejection, service-scoped approval,
unapproved CRITICAL rejection and policy acquisition failure. Preserve all five
existing callers' regression tests.

Local result: `npm run ci` passed with 253 action tests and 40 local-tool tests.
A temporary Git index held generated output for the drift check; the normal
index is unchanged. Read-only review found no blocking enrollment issue.

## Dependencies and rollback

After review/release, environments must add service v3 profiles and v3 receipt
schemas, plus an explicit operator-owned transition route. Keep its service v1
default until consumer activation is ready. Producer adoption follows that
reader capability and pins the actual reviewed enrollment release for both
actions and PR/local tooling. Do not invent a release SHA or use mutable refs.

Service adoption must preserve strict v1 historical verification. Default v3
activation follows a separately authorized exact-run canary publication and
admission. No producer may select the admission policy, and no schema fallback
is allowed. Live GitHub/registry/AWS work requires separate authorization.

Existing consumers are unaffected by this additive release until they change
pins. Reverting their pin remains safe. A newly adopted service cannot revert
to a pre-enrollment shared release; restore its original local v1 producer or
use a corrected enrollment release. Keep dual environments readers for retained
v1/v3 candidates and receipts. No application or deployment changes are included.
