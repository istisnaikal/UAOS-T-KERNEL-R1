# Maintainers

Roles and how to earn them are defined in [GOVERNANCE.md](GOVERNANCE.md).

| Name | GitHub | Roles | Areas |
|---|---|---|---|
| Kistisnai Kaide | [@istisnaikal](https://github.com/istisnaikal) | Maintainer, security maintainer | all |

## The single-maintainer risk, stated plainly

The project has one maintainer, who is also its only security owner. A sole code owner cannot
approve their own pull request. The controls that exist instead:
- every merge-lane gate is proven to fail on a seeded violation (`cargo xtask negative`);
- a 24-hour cool-off applies to cryptography, `unsafe` code, contract freezes and gate removals.

These controls are weaker than a second human reviewer, and we say so.
