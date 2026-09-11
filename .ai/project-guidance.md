# Project AI Guidance

This repository owns reusable GitHub Actions used by Movie Reservation Platform
Lab delivery workflows. Treat every action change as supply-chain code because
it executes with the caller job's permissions.

## Repository layout

- `actions/*/action.yml`: public composite-action interfaces and orchestration.
- `actions/container-evidence/src/`: reviewed TypeScript source.
- `actions/container-evidence/lib/`: checked-in JavaScript executed by callers.
- `contracts/`: versioned, closed evidence schemas.
- `test/`: offline contract and security regression tests.
- `local-tools/container-security/`: local scan/evaluate helper; its source,
  generated JavaScript, and dedicated offline tests live in `src/`, `lib/`, and
  `test/`. Producer builds remain documented and separate.
- `docs/`: caller obligations, migration plans, versioning, and rollback.
- `.github/workflows/`: credential-free repository verification.
- `.ai/`: canonical AI guidance. Generated assistant files and `AGENTS.md`
  come from `.ai/sync.sh`.

## Development commands

- Install: `npm ci --ignore-scripts`
- Compile TypeScript: `npm run build`
- Test: `npm test`
- Local-tool tests only: `npm run test:local-tools`
- Full local CI equivalent: `npm run ci`
- Dependency audit: `npm audit --audit-level=high`
- Diff hygiene: `git diff --check`

Run `npm run ci` after source changes. It recompiles TypeScript, verifies that
checked-in JavaScript matches the source, and runs the offline contract suite.

## Contract and implementation rules

- Preserve action inputs, outputs, profile identities, schema versions, and
  evidence file layout unless a coordinated compatibility plan changes them.
- Keep publication policy closed and allowlisted. Arbitrary repository, path,
  signer, workflow, image, or artifact inputs must not become caller-controlled.
- Keep pure policy in focused modules and isolate filesystem, Git, GitHub CLI,
  process, and workflow-output adapters.
- Validate environment variables and external documents at runtime; TypeScript
  types do not validate runner input.
- Edit TypeScript under `src/`, regenerate `lib/`, and commit both. Do not
  hand-edit generated JavaScript.
- Keep action dependencies and consumer references pinned to reviewed full
  commit SHAs.
- Keep repository CI credential-free and ordinary tests offline. Live
  publication, attestations, registry scans, admission, and deployment require
  separate explicitly authorized acceptance work.

## Security boundaries

- Do not expose tokens, attestation bundles, child-process stderr, private
  configuration, environment bindings, or workspace-wide artifacts.
- Preserve exact-subject provenance verification, hosted-runner enforcement,
  bounded regular-file checks, workspace/temp containment, exclusive writes,
  rejected-evidence separation, and the configured vulnerability gate.
- Keep publisher permissions in caller workflows. Shared actions must not grant
  themselves broader authority or introduce AWS credentials.
- Do not merge, publish images, dispatch workflows, admit artifacts, deploy, or
  change AWS/environment state without explicit user instruction.

## Planning, tests, and documentation

- Use `principal-engineer-planner` for contract versions, new action
  interfaces, trust-boundary changes, or cross-repository migrations. Small pin
  and wording updates can use the existing issue plan.
- Add behavior-focused tests for security or contract changes. Prefer temporary
  directories and fake executables over network, registry, GitHub, or AWS calls.
- Update caller documentation and migration dependencies with action behavior.
  Document rollback as reverting the consumer's full-SHA pin.
