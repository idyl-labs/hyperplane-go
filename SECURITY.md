<!-- Copyright 2026 Idyl Labs. SPDX-License-Identifier: Apache-2.0 -->

# Security Policy

## Supported versions

Only the latest release receives security fixes.

## Reporting a vulnerability

Report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/idyl-labs/hyperplane-go/security/advisories/new).
Do not open a public issue.

If you cannot use GitHub Security Advisories, email **security@idyl.dev**
with the subject prefix `[SECURITY]`.

You can expect:

- an acknowledgement within 3 business days;
- an initial assessment within 10 business days;
- a fix or mitigation coordinated with you before public disclosure.

We ask that you keep the report private until a fix has shipped and a
disclosure date has been agreed. Our default target is 90 days from the
report, sooner for issues under active exploitation. We credit reporters
unless they prefer to remain anonymous.

## Scope

In scope: the code in this repository, including the admission contract's
verification logic, the dock handshake, the transports, and the handling of
generations and other secrets.

The Hyperplane edge and the services that issue credentials are not in this
repository. Report issues in them the same way and we will route them.
