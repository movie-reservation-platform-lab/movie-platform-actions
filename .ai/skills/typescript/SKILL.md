---
name: typescript
description: Use when designing or refactoring TypeScript types, runtime validation, ESM modules, and generated JavaScript for the Node 24 action runtime.
---

# TypeScript

Use explicit types where they expose the closed contract or prevent unsafe
runner input from being treated as trusted.

- Keep strict TypeScript enabled and avoid `any`.
- Model closed component, subject-kind, severity, and evidence values with
  unions or readonly maps.
- Accept environment, JSON, and process output as untrusted values and validate
  them at runtime before narrowing their types.
- Distinguish compile-time checks from runtime authorization and schema
  validation in explanations and reviews.
- Keep Node 24 ESM imports explicit. TypeScript `.mts` sources compile to the
  checked-in `.mjs` files consumed by composite actions.
- Edit `actions/container-evidence/src/`, run `npm run build`, and never
  hand-edit `actions/container-evidence/lib/`.
- Preserve observable errors and exit behavior when converting or refactoring
  an action entrypoint.

Run `npm run ci` after changes so generated drift and behavior regressions are
both detected.
