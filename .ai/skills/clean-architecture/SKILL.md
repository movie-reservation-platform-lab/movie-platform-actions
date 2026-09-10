---
name: clean-architecture
description: Use when designing or reviewing dependency direction and policy/adapter boundaries in repository-authored GitHub Action code; do not impose service-layer structure on simple composite metadata.
---

# Clean architecture for shared actions

Apply architectural boundaries where they make security policy easier to test
and review.

- Keep profile selection, admission rules, and value validation pure.
- Keep Git, GitHub CLI, filesystem, environment, and workflow-output operations
  in narrow adapters or executable entrypoints.
- Treat each executable module as a composition root for the policy it invokes.
- Make the innermost module own any interface it needs from an external tool.
- Pass only validated, bounded values from adapters into policy code.
- Keep composite YAML responsible for step order, permissions expected from the
  caller, and immutable third-party action references.

Avoid adding domain/application/infrastructure folder hierarchies when a small
pure function and one adapter make the dependency direction clear. Extract a
port only when it removes real coupling, makes a security boundary explicit, or
allows deterministic tests.

When reviewing a change, trace inputs from action metadata and runner
environment through validation, external commands, retained files, and action
outputs. Confirm that policy code cannot choose arbitrary repositories, signer
workflows, paths, or artifact names.
