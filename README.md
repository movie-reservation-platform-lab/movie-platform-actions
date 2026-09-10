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

## Development

The reviewed TypeScript source is in
`actions/container-evidence/src/`. GitHub runners execute the compiled
JavaScript checked into `actions/container-evidence/lib/`.

```sh
npm ci --ignore-scripts
npm run ci
```

`npm run ci` compiles the TypeScript, fails if generated JavaScript differs
from the checked-in files, and runs the offline contract and security tests.
Node 24 is the supported development and action runtime.

## AI guidance

Canonical repository guidance, reusable skills, and read-only review agents
live under `.ai/`. After changing them, run `bash .ai/sync.sh` and review the
generated assistant-specific files together with the canonical source. The
assistant-specific directories are local and gitignored; `.ai/` and the
generated root `AGENTS.md` are committed, matching the sibling repositories.
