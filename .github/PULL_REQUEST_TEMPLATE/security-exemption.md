## Exemption request

Apply the `security-exemption` label. This template records review; it does not
grant approval. Do not bundle an exemption with unrelated action code changes.

- Operation: request / renew / remove / emergency withdrawal
- Record path(s) and exemption ID(s):
- Component and accountable owner for each record:
- CVE, package name, installed version, and exact PURL (including qualifiers):
- Type: not affected / risk accepted
- Primary advisory or analysis reference(s):
- Why the assessment or acceptance applies to this component/platform:
- Remediation or next-review actions (required for accepted risk):
- Approval date and expiry (maximum 30 days accepted risk / 90 days not affected):
- Original complete scan report / reproduction reference:
- For renewal: what was reviewed again and why a fix/removal is not appropriate:
- For withdrawal: affected consumers, pause/update procedure, and old-evidence rejection check:

## Checks

- [ ] One explicit record per component/CVE/versioned package; no wildcard scope.
- [ ] OpenVEX impact status matches the type; accepted risk is still `affected`.
- [ ] Record links to this PR; owner, rationale, references and expiry are complete.
- [ ] `npm run ci` passes; synthetic fixture records were not added as real approvals.
- [ ] Producer/admission pin updates and fresh-evidence requirements are identified.
- [ ] Renewals increment VEX version and record a new explicit approval decision.

## Maintainer decision

- Approver:
- Decision, rationale, and UTC time:

Current lab authority is @patex1987, including their own requests. Do not describe
self-review as independent security-team approval. Merging support code alone does
not approve this vulnerability, publish an image, or authorize admission/deployment.
