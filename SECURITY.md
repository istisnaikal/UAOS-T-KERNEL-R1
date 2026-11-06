# Security Policy

UAOS holds API keys and sees agent traffic. We treat its security as the product.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub's *private vulnerability
reporting*: the repository's "Security" tab, then "Report a vulnerability". Reports reach the
maintainers only.

Please include: affected version or commit, platform, reproduction steps, and impact. Redact any
real secrets; never send us live credentials.

## What to expect

| Severity | Examples | Acknowledge | Fix or mitigation advisory |
|---|---|---|---|
| S1 | secret leak, RCE, data loss, budget runaway | 24 hours | 72 hours |
| S2 | durability, crash, provider cascade | 3 days | next patch release |
| S3 | hardening, UX/performance with security relevance | 7 days | release train |

- Coordinated disclosure with a default **90-day embargo**, shortened if a fix ships earlier or
  the issue is exploited in the wild.
- Advisories and CVEs are published through GitHub Security Advisories, with credit if you want it.
- Embargoed fixes are developed in a private fork and released as signed patch releases.

## Scope

In scope: the code in this repository, its release artifacts, and its release pipeline. Out of
scope: vulnerabilities in model providers or third-party tools themselves (report those
upstream; we will help if UAOS amplifies them).

## Our commitments

- Security fixes are released to everyone, at once.
- Claims are measured: we say "tamper-evident", not stronger, and every security claim names the
  test or corpus behind it.
