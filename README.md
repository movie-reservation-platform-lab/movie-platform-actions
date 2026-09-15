# Movie Platform Actions

Reusable, security-sensitive GitHub Actions for the Movie Reservation Platform
Lab. Consumers must pin these actions to a reviewed full commit SHA.

The initial actions prepare and attest runnable container candidates:

- `actions/prepare-container-candidate` validates canonical `main`
  publication through the authenticated GitHub API and creates attempt-unique
  discovery metadata. Pass `github-token: ${{ github.token }}`; the lookup
  requires `contents: read` in the caller job.
- `actions/container-evidence` verifies provenance, records an SBOM and
  complete vulnerability report, enforces the provisional CRITICAL gate, and
  emits a closed four-file evidence package (strict v1alpha2 by default,
  governed approvals with explicit v1alpha3 selection).

See [the action contract](docs/container-candidate-actions.md) for supported
components, caller permissions, pinning, rollback, and admission boundaries.

To build and check an image before publication, use the
[local vulnerability scanning runbook](docs/local-container-vulnerability-scanning.md).
The scan/evaluate helper and its dedicated tests live in
[`local-tools/container-security/`](local-tools/container-security/).

The [governed exemption contract](docs/vulnerability-exemption-contract.md) is
available through explicit v1alpha3 hosted/local runtime selection. Each evaluation
retrieves the latest reviewed central approvals and blocks every unapproved CRITICAL,
retaining complete findings and decisions. Legacy invocations remain strict.
Admission independently applies current approvals to original verified findings.
No exemption is active. The [runtime plan](docs/plans/governed-exemption-runtime-integration.md)
keeps producer adoption, hosted admission activation and actual approvals separate.

## Development

The reviewed TypeScript source is in
`actions/container-evidence/src/`. GitHub runners execute the compiled
JavaScript checked into `actions/container-evidence/lib/`.

```sh
npm ci --ignore-scripts
npm run ci
```

`npm run ci` compiles TypeScript, compares generated JavaScript with the **Git
index** (including detection of untracked generated files), and runs the offline
contract and security tests. After editing TypeScript: run `npm run build`,
review the source/generated diff, stage the reviewed source and `lib/` changes,
then run `npm run ci`. Correct but unstaged build output will fail the generated
check. Commit both source and generated files together.
Node 24 is the supported development and action runtime.
The build/generated checks also cover `local-tools/container-security/src/` and
`lib/`. Run only its offline suite with `npm run test:local-tools`; `npm test`
runs both the hosted-action and local-tool suites.

Repository CI checks live in [`ci_automations/`](ci_automations/README.md):
the quality checks for these CI building blocks themselves.

### Reading the code and tests

Start with the two `action.yml` files to see step order and caller inputs. Source
under `actions/container-evidence/src/` is organized by responsibility:

| Question | Read first | Behavior examples |
| --- | --- | --- |
| Who may publish, and is this current main? | `profile.mts`, `prepare.mts`, `canonical-main.mts` | `test/prepare.test.mjs` |
| How is provenance bound to the image and workflow? | `verify.mts` | `test/container-evidence.test.mjs` |
| Which evidence version is written? | `context.mts`, `write-candidate-evidence.mts`, `candidate-v3.mts` | `test/container-evidence.test.mjs`, `test/runtime-v3.test.mjs` |
| How are approvals acquired and applied? | `policy-source.mts`, `approved-evaluation.mts`, `vulnerability-policy.mts` | `test/policy-source.test.mjs`, `test/vulnerability-policy.test.mjs` |
| How do unsafe legacy reports fail? | `evaluate-vulnerabilities.mts`, `runtime-files.mts` | `test/legacy-safety.test.mjs` |
| How does local scanning run and clean up? | `local-tools/container-security/src/scan.mts`, `trivy-runner.mts` | `local-tools/container-security/test/scan.test.mjs` |

Default v1alpha2 rejects every CRITICAL. Explicit v1alpha3 evaluates reviewed
approvals and rejects every **unapproved** CRITICAL. Tests execute generated
JavaScript with temporary files and fake external operations; they require no
GitHub, registry or AWS credentials.

The GitHub ruleset [Require shared action CI on main](https://github.com/movie-reservation-platform-lab/movie-platform-actions/rules/22754075)
requires the `offline-contract-tests` check from GitHub Actions to pass and the
branch to be up to date before merging into `main`. This ruleset is configured
in GitHub repository settings.

## AI guidance

Canonical repository guidance, reusable skills, and read-only review agents
live under `.ai/`. After changing them, run `bash .ai/sync.sh` and review the
generated assistant-specific files together with the canonical source. The
assistant-specific directories are local and gitignored; `.ai/` and the
generated root `AGENTS.md` are committed, matching the sibling repositories.
