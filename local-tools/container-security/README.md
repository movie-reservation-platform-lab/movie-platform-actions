# Local container vulnerability check

Build your producer's production image for `linux/amd64`, then scan its local tag:

```sh
node /path/to/movie-platform-actions/local-tools/container-security/lib/scan.mjs my-service:local
```

Use a checkout at a reviewed full commit SHA. Requires Node 24 and Docker through
a local Unix socket; no npm install, compilation, or host Trivy installation.
The helper scans an existing image and reuses the shared CRITICAL evaluator.

Complete reports and a short summary go into a fresh directory under
`.local-container-security/` in your current directory. Change that root with
`--output-dir /path/to/reports`. Exit 0: no CRITICAL findings; 1: CRITICAL findings;
2: the check could not complete. Complete reports survive policy rejection.

Read the [runbook](../../docs/local-container-vulnerability-scanning.md) for the
worked producer example, Docker socket trust, cache, failure handling, and cleanup.
Local diagnostics are not PR authority or admissible candidate evidence.

## Development

Source is in `src/`, checked-in generated runtime code in `lib/`, and this tool's
offline tests in `test/`.

- `src/scan.mts` is the CLI: validates setup, saves reports, and applies the shared policy.
- `src/trivy-runner.mts` runs the Trivy container: collects bounded output, handles
  timeout/interruption, and attempts cleanup after failure.

Run from the repository root:

```sh
npm ci --ignore-scripts
npm run build
npm run test:local-tools
```

Include source and generated changes together. `npm run ci` checks both generated
directories and runs the hosted-action and local-tool suites. The local tests use
fake Docker commands and the real shared evaluator; they never scan real images.
