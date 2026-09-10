---
name: testing
description: Use when writing or reviewing Node test coverage for shared GitHub Actions, generated JavaScript, evidence schemas, workflow metadata, and security failure paths.
---

# Testing shared actions

Test observable contracts and trust-boundary failures with Node's built-in test
runner.

- Execute the checked-in JavaScript that caller workflows will run.
- Use temporary workspaces and fake `git` or `gh` executables for process
  adapters; ordinary tests must not call GitHub, registries, Trivy, OIDC, or AWS.
- Assert success outputs and retained files, plus refusal of unsupported
  components, contexts, digests, subjects, schemas, severities, paths,
  symlinks, overwrites, stale revisions, and signer constraints.
- Verify exact artifact membership and immutable third-party action pins when
  composite metadata changes.
- Keep test inputs small and bounded. Avoid fixtures that hide the environment
  or filesystem state establishing a security scenario.
- Add a regression test when a failure could weaken admission, disclose
  process output, or produce ambiguous evidence.

Use focused tests while iterating, then run:

```sh
npm ci --ignore-scripts
npm run ci
git diff --check
```

`npm run ci` must compile source, compare generated JavaScript with the
checked-in output, and run the offline suite.
