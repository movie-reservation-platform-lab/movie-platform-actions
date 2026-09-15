# Container candidate actions (experimental)

Owned by the organization CI maintainers under
[movie-platform-actions #1](https://github.com/movie-reservation-platform-lab/movie-platform-actions/issues/1),
as a bounded extraction from
[organization issue #12](https://github.com/movie-reservation-platform-lab/.github/issues/12).
The known-good reservation-service pilot remains unchanged.

Use both actions by **the same reviewed full commit SHA**:

```yaml
- id: candidate
  uses: movie-reservation-platform-lab/movie-platform-actions/actions/prepare-container-candidate@<full-reviewed-commit>
  with:
    component: recommendation-service
    github-token: ${{ github.token }}
# Caller builds and pushes one linux/amd64 manifest with provenance: false,
# tags: ${{ steps.candidate.outputs.image_ref }}:${{ steps.candidate.outputs.tag }}
- uses: movie-reservation-platform-lab/movie-platform-actions/actions/container-evidence@<same-full-reviewed-commit>
  with:
    component: recommendation-service
    digest: ${{ steps.build.outputs.digest }}
    github-token: ${{ github.token }}
```

Caller obligations: Node 24, git, gh, Docker; canonical repository push/main guard; main publication must not be cancelled by concurrency; checkout persist-credentials:false; existing quality/smoke gates; contents:read, packages:write, id-token:write, attestations:write only in the publishing job. Do not install application dependencies in that privileged job.

### Prepare authentication and troubleshooting

Prepare requires an explicit `github-token: ${{ github.token }}` input. Its
minimum job permission is:

```yaml
permissions:
  contents: read
```

The full publishing job still needs its separate package/attestation/OIDC
permissions listed above. Passing the job token to prepare does not reduce that
token's permissions. The committed expression is a reference; GitHub supplies
the actual token at runtime. Prepare receives it only through its step environment
and sends it in an HTTPS authorization header. It never retains or prints it.

The lookup uses the closed component profile's repository on `api.github.com`,
requires the GitHub.com server/API environment, and requests exactly
`git/ref/heads/main`. It accepts one valid commit matching `GITHUB_SHA` before
writing outputs. There is one attempt, a 30-second total deadline including the
body, a 4096-byte response limit, and no redirects, retries or anonymous fallback.

Failures use fixed codes and messages on stderr. No response body or transport
diagnostics are exposed. For example:

```text
[prepare-container-candidate] canonical-main-timeout: GitHub lookup exceeded 30 seconds.
```

| Code | What to check |
| --- | --- |
| `invalid-publication-context` | Canonical component/repository, push/main, job ID, source/run identifiers, `GITHUB_SERVER_URL` and `GITHUB_API_URL`. |
| `invalid-github-token` | Pass the required token input; do not add whitespace or print the value to debug it. |
| `canonical-main-unavailable` | Repository `contents: read` access, main branch existence, connectivity, GitHub availability/rate limits. This code alone does not distinguish denied access from an unavailable resource. |
| `canonical-main-timeout` | Restore connectivity or wait for GitHub recovery before rerunning. |
| `canonical-main-response-too-large` | Review the API response contract/limit; never paste raw responses into public logs. |
| `canonical-main-invalid-response` | Review the expected ref/commit response contract and API behavior. |
| `stale-main-revision` | Use a workflow run for the current main commit; rerunning an old commit cannot make it current. |
| `prepare-output-failed` | Runner-managed `GITHUB_OUTPUT` setup and file access. |
| `prepare-failed` | Reviewed action code and runner setup; no raw exception is printed. |

Upgrade both shared-action pins to the same reviewed full SHA and add the prepare
token input in one consumer PR. Start with recommendation-mcp, validate adoption,
then update remaining consumers separately. Roll back both pins and the prepare
input together. Offline CI verifies code behavior; private-organization permissions
are checked during migration. The [authentication audit](reviews/github-authentication-portability.md)
records separate central-policy and scanner follow-ups.

Supported components: reservation-agent, recommendation-service, reservation-mcp, recommendation-mcp and **reservation-web ECS image only**. Profiles bind repository, workflow and job; arbitrary artifacts/signer workflows are not inputs. Source/build labels remain caller-owned. The API job display name is recorded in workflow.job and checked separately from the YAML job ID at publication.

The output is `<component>-security-evidence-<runId>-attempt-<attempt>`, four exact files following [v1alpha2](../contracts/component-candidate-evidence-v1alpha2.schema.json) by default. Files are rooted directly in the downloaded artifact; document paths include the producer's security-evidence/ prefix. Image provenance and package provenance are both required. The digest must identify a single runnable manifest, not an OCI index or web static bundle.

CRITICAL findings fail; HIGH findings are exposed for explicit downstream approval under provisional [policy #8](https://github.com/movie-reservation-platform-lab/.github/issues/8). A failed run or rejected-diagnostics artifact is never admission evidence. Publication success does not mean selected, admitted to AWS, deployed, or behaviorally tested at that exact digest.

The default v1alpha2 evaluator and writer accept vulnerability reports only as
bounded regular files within the workspace (64 MiB maximum; no symlinks or hard
links). Invalid reports fail with controlled diagnostics, without echoing report
content or raw filesystem errors. V3 retains its separately documented limits.

Local checks: `npm ci --ignore-scripts && npm run ci` (Node 24). TypeScript
source is compiled into the checked-in `actions/container-evidence/lib/`
JavaScript; CI fails if regeneration changes those files. Ajv is
development-only, for emitted-document/schema compatibility tests; publisher
jobs never install these dependencies. Fake HTTPS/gh adapters keep tests offline;
Trivy, OIDC and real canonical publication need separate live acceptance.
Runner-provided gh is used in producer verification as in the pilot; the
environment verifier independently uses its pinned CLI. This does not make
producer runner tools immutable.

For a producer-owned local build followed by the shared diagnostic scan, see
[the local container vulnerability runbook](local-container-vulnerability-scanning.md).
Its helper reuses this action's CRITICAL evaluator, but produces no candidate
evidence or admission authority.

Versioning: review changes here, run tests, merge, then open consumer pin PRs. Never consume main/tags or silently rewrite an existing schema contract. In emergencies revert affected consumer pins; do not bypass validation. Existing artifacts expire after 14 days: new runs are required, not reconstructed evidence.

## Governed approvals with v1alpha3

Select `evidence-version: v1alpha3` on `container-evidence` when the consumer is
ready for the new format. Omitting it keeps the existing strict v1alpha2 behavior.
V3 automatically evaluates approved exemptions; there is no separate enable switch.
The five existing component identities and both actions' full-SHA pins remain unchanged
until a separately reviewed consumer update selects the new implementation.

For each v3 run, the action authenticates directly to GitHub using `github-token`,
resolves this central repository's approved main once and reads that revision's
selected-component Git trees/blobs. The token must have read access to the actions
repository as well as the existing producer capabilities. The source repository,
branch and paths are fixed; no policy-file or policy-revision input is accepted.
Only complete authoritative listings establish an empty policy. A failed lookup,
invalid record or expired coverage cannot silently pass. The resolved policy SHA
is recorded separately from the reviewed action implementation pin.

V3 uses the same digest-pinned Trivy 0.70.0 container as the local helper, with
explicit complete-report settings and no producer workspace/config mounts. It
scans the exact GHCR digest remotely with a temporary GHCR-only Docker auth file,
mounted read-only and removed after scanning, and no hosted scan cache. Global
registry username/password variables are not passed to Trivy or its DB mirrors. Default Trivy config,
ignore files, inherited `TRIVY_*` overrides and producer-supplied VEX/rego filters
cannot suppress findings. Each scan is bounded to six minutes including container
startup and 16 MiB output. The Docker daemon must be available at the standard
hosted Linux runner socket. No npm installation or host Trivy installation is needed.

The candidate document becomes `component-candidate-evidence-v1alpha3.json`.
The other three files and artifact names remain the same. All raw counts and
original findings remain visible. `passed-with-exemptions` is distinct from
`passed`; any unapproved CRITICAL blocks candidate creation. Used approvals,
rationale/expiry, decisions, source revision and report hash are embedded in the
candidate. Only these exact four files are attested/uploaded as canonical evidence.
The diagnostic JSON is included only in rejected artifacts, never as a fifth
canonical member. Summaries may abbreviate large finding tables and point to the
complete retained JSON; policy decisions are never truncated.

V3 bounds match the environments reader: 1 MiB actual candidate bytes, 768 KiB
compact evaluation, 4 MiB provenance and 16 MiB each for report/SBOM. Legacy limits
are unchanged. Over-limit/operational errors fail and identify the applicable local
reproduction path; there is no per-run bypass. Candidate and rejected artifacts
retain the existing 14-day retention and run/attempt discovery naming.

Environments #91/#93 implement independent latest-policy acquisition and admission;
#95 adds read-only diagnostics. Its hosted workflows still require separate v3
activation. A producer's historical approval does not select admission's current
policy. Renewals can cover an original finding without rebuilding; withdrawal or
expiry can block the next admission attempt. No second fetch or expiry gate is added
to an in-flight decision.

Recommendation MCP is the intended first adopter. Its separate update must replace
the proposed standalone fail-every-CRITICAL PR scan with the shared local v3 command
and update the publication action together. An exemption request is a separate
reviewed central-policy PR. Neither this tooling change nor a green diagnostic
approves a vulnerability. Coordinate hosted admission activation before using v3
packages there. Rollback means reverting the consumer's full-SHA pin and associated
version selection, restoring strict checks.

## Migration dependencies

This repository's replacement PR supersedes
[the original organization-profile PR](https://github.com/movie-reservation-platform-lab/.github/pull/13).
These producer PRs must all pin the same reviewed full commit from this
repository before they are ready to merge:

| Component | Producer PR |
| --- | --- |
| reservation-agent | [movie-reservation-agent #16](https://github.com/movie-reservation-platform-lab/movie-reservation-agent/pull/16) |
| recommendation-service | [movie-recommendation-service #9](https://github.com/movie-reservation-platform-lab/movie-recommendation-service/pull/9) |
| reservation-mcp | [movie-reservation-mcp #8](https://github.com/movie-reservation-platform-lab/movie-reservation-mcp/pull/8) |
| recommendation-mcp | [movie-recommendation-mcp #8](https://github.com/movie-reservation-platform-lab/movie-recommendation-mcp/pull/8) |
| reservation-web ECS image | [movie-reservation-web #15](https://github.com/movie-reservation-platform-lab/movie-reservation-web/pull/15) |

Environment verification remains tracked in
[movie-platform-environments #82](https://github.com/movie-reservation-platform-lab/movie-platform-environments/issues/82).

Repository administrators should require reviewed PRs/status checks and CODEOWNERS review for actions/, contracts/ and .github/workflows/. No branch protection or organization settings are changed by this PR. Shared code executes with caller write permissions; review it as supply-chain code.

See [plan](plans/shared-container-evidence.md), [GitHub attestation verification](https://cli.github.com/manual/gh_attestation_verify) and [composite metadata](https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax).
