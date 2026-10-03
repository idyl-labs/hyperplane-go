<!-- Copyright 2026 Idyl Labs. SPDX-License-Identifier: Apache-2.0 -->

# Contributing

Thank you for your interest in hyperplane-go.

## Before you start

For anything beyond a small fix, open an issue first to agree on the change.
The protocol definitions, the admission contract and the conformance corpus
are shared with other implementations, so changes to them are design changes,
not code changes.

## Development

You need Go 1.26.4 or later and Git. Every check CI runs is available
locally:

```sh
make check     # tidiness, dependencies, license headers, lint, generated code, tests, vulnerabilities
make test      # tests with the race detector
make lint      # golangci-lint, pinned
make fmt       # format code and imports
make cover     # test coverage
make breaking  # protocol changes that break compatibility with main
make proto     # regenerate code after editing a .proto file
```

All targets run with `GOWORK=off`, so they test this module exactly as its
users receive it.

## Standards

**Compatibility.** Every exported identifier is a long-term commitment.
Wire-visible strings, field numbers, enum values and canonical encodings are
part of the protocol and change only through a new protocol version.

**Errors.** New error strings are lowercase and start with the package name.
Wrap causes with `%w`. Callers classify errors with `errors.Is` and
`errors.As` against the sentinels and types each package exports, never by
matching text.

**Secrets.** A dock generation's nonce is a secret. No error or log line
produced by this module contains it; render a generation with
`wire.RedactGen`.

**Concurrency and cancellation.** Operations that wait on the edge take a
`context.Context` and return when it is done. Streams are released on every
path, including errors.

**Tests.** Test fixtures use reserved names only, such as domains under
`example.com`. The conformance corpus is regenerated only by
`wire/internal/admissioncorpusgen`, and a change to it is a protocol change.

**Comments.** Document what an exported identifier guarantees, not how it
came to be.

## Commits

Sign off every commit to certify the
[Developer Certificate of Origin](https://developercertificate.org):

```sh
git commit -s
```

By contributing, you agree that your contributions are licensed under the
Apache License 2.0.
