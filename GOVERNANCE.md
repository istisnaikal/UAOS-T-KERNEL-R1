# Governance

## Red lines

These hold for every change, and no vote can trade one away. Code and gates cite them by number.

1. Data stays local. Contact with anything outside the machine is opt-in, minimal and visible.
2. Secrets are never logged raw. High-risk redaction fails closed.
3. An irreversible side effect is reported as such, never as rolled back.
4. Nothing acts on its own without a capability sandbox, an audit trail and a policy or an
   approval.
5. Security, privacy, the journal and the basic budget controls are never withheld from anyone.
6. Every claim is carried by a metric, a baseline or a test; words that promise more are
   refused.
7. Licensing, provider terms and the handling of user data are reviewed before a release.
8. Overhead is measured and kept small; nothing claims a speed it has not measured.
9. A lasting change to the outside world is never invisible.
10. An unknown is marked as a decision, an assumption or an option, never invented.

## Roles

| Role | Can | Becomes one by |
|---|---|---|
| Contributor | open issues and PRs | contributing |
| Triager | label, deduplicate, reproduce | sustained helpful triage; nominated by a maintainer |
| Area reviewer | approve PRs in one area | sustained quality contributions in that area |
| Maintainer | merge, release, set direction | nomination and lazy consensus of maintainers |
| Security maintainer | handle embargoed reports; veto a change that crosses a red line | maintainer with demonstrated security judgement |

Current holders are listed in [MAINTAINERS.md](MAINTAINERS.md).

## Decisions

- **Reversible decisions** are made by lazy consensus within 24 hours.
- **Expensive decisions** (contracts, architecture, security posture, licensing) need an RFC
  ([`docs/rfcs/`](docs/rfcs/)) with a threat and privacy note and a test plan, and at least 48
  hours of review.
- A security maintainer's veto must name the missing proof and an alternative.

## Reviews and CODEOWNERS

Critical paths (contracts, state, platform OS and crypto code, identity, policy, ledger,
redaction, egress, CI workflows, schemas) require review by a security owner. A solo maintainer
applies a 24-hour cool-off instead of a review by a second person, and records it as a residual
risk, not as an equivalent.

Every pull request goes through a full review, its fixes, one focused pass over the fix diff and
everything it touches, and a final full review before it leaves draft.

## Conduct

All spaces follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Report a conduct problem privately
through the repository's private vulnerability reporting form ("Security" tab, "Report a
vulnerability") with the title prefix `[CONDUCT]`; it reaches maintainers only and is never
published.

## Changing this document

Changes to governance follow the expensive-decision path.
