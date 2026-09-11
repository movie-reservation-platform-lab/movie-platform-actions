# Movie Platform Actions

Reusable, security-sensitive GitHub Actions for the Movie Reservation Platform
Lab. Consumers must pin these actions to a reviewed full commit SHA.

The initial actions prepare and attest runnable container candidates:

- `actions/prepare-container-candidate` validates canonical `main`
  publication and creates attempt-unique discovery metadata.
- `actions/container-evidence` verifies provenance, records an SBOM and
  complete vulnerability report, enforces the provisional CRITICAL gate, and
  emits the closed v1alpha2 four-file evidence package.

See [the action contract](docs/container-candidate-actions.md) for supported
components, caller permissions, pinning, rollback, and admission boundaries.

To build and check an image before publication, use the
[local vulnerability scanning runbook](docs/local-container-vulnerability-scanning.md).
The scan/evaluate helper and its dedicated tests live in
[`local-tools/container-security/`](local-tools/container-security/).

The [governed exemption contract](docs/vulnerability-exemption-contract.md) is
foundation work for a later opt-in rollout. No exemption is active and the
current action/local CLI still reject CRITICAL findings.

## Development

The reviewed TypeScript source is in
`actions/container-evidence/src/`. GitHub runners execute the compiled
JavaScript checked into `actions/container-evidence/lib/`.

```sh
npm ci --ignore-scripts
npm run ci
```

`npm run ci` compiles the TypeScript, fails if generated JavaScript differs
from the checked-in files (including newly generated, untracked files), and runs
the offline contract and security tests. After editing TypeScript, run
`npm run build` and commit both the source and generated `lib/` changes.
Node 24 is the supported development and action runtime.
The build/generated checks also cover `local-tools/container-security/src/` and
`lib/`. Run only its offline suite with `npm run test:local-tools`; `npm test`
runs both the hosted-action and local-tool suites.

Repository CI checks live in [`ci_automations/`](ci_automations/README.md):
the quality checks for these CI building blocks themselves.

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
