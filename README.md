<!-- Copyright 2026 Idyl Labs. SPDX-License-Identifier: Apache-2.0 -->

# hyperplane-go

[![CI](https://github.com/idyl-labs/hyperplane-go/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/idyl-labs/hyperplane-go/actions/workflows/ci.yml?query=branch%3Amain)
[![Go Reference](https://pkg.go.dev/badge/github.com/idyl-labs/hyperplane-go.svg)](https://pkg.go.dev/github.com/idyl-labs/hyperplane-go)

The Go client for Hyperplane, the authenticated connection fabric of
[IDYL](https://idyl.network).

An endpoint (a node, a pod, one leg of a session, a share) connects to a
Hyperplane edge with a *dock*: one mutually authenticated connection over
QUIC, or over TCP and TLS where UDP is blocked. Through its dock, the
endpoint receives lanes to other endpoints, events and RPCs, without opening
a listening port of its own, and reaches other endpoints the same way.

```go
d, err := dock.Open(ctx, dock.Config{
	Endpoint: "edge.example.com:443",
	ServerID: edgeID,  // the edge's exact SPIFFE ID
	Bundles:  bundles, // trust anchors for the edge
	SVID:     svid,    // the endpoint's X.509 SVID
	Admission: &dock.DemandAdmission{
		LeaseEnvelope: lease,  // the signed admission lease for this SVID
		Signer:        svidKey, // the SVID's Ed25519 private key
	},
})
if err != nil {
	return err
}
defer d.Close()

for {
	lane, err := d.AcceptLane(ctx)
	if err != nil {
		return err
	}
	go serve(lane)
}
```

The [`dock` package documentation](dock/doc.go) covers the
complete surface: redocking with a predecessor generation, drain signals,
session resumption, the transports, and lanes.

## Packages

| Package | Contents |
| --- | --- |
| [`dock`](dock) | The client: open a dock; accept and open lanes, events and RPCs; lane streams and flows. |
| [`wire`](wire) | Framing, canonical encoding, admission lease and dock proof verification, and the lane stream header. |
| [`wire/fallback`](wire/fallback) | `fallback/1`, the TCP and TLS transport used where UDP is blocked. |
| [`wire/svidtest`](wire/svidtest) | Test certificate authorities and admission signers. |
| [`generation`](generation) | The edge tag and dock generation identity types. |
| `wire/admissionv3`, `wire/dockv2`, `wire/dockv3`, `wire/deliveryv2`, `wire/commonv2`, `wire/mintingv2`, `wire/trustv1` | Generated protocol code, with the contract constants and validators that belong to each protocol. |

## Protocol

The protocol definitions under [`wire/proto`](wire/proto) are the contract;
every message is documented there. Signed protobuf messages use the canonical
encoding implemented in [`wire`](wire), and
[`wire/testdata/admissionv3-conformance`](wire/testdata/admissionv3-conformance)
holds a language-neutral corpus that every implementation of lease
verification must reproduce verdict for verdict.

| Identifier | Value |
| --- | --- |
| ALPN over QUIC | `idyl/2` |
| ALPN over TCP and TLS | `idyl-fallback/1` |
| Dock contract without admission material | `dock/2` |
| Dock contract with demand admission | `dock/3` |
| Admission lease contract | `zone-admission-lease/3` |

## Terms

| Term | Meaning |
| --- | --- |
| Endpoint | Anything that docks: a node, a pod, one leg of a session, a share. |
| Edge | The fabric server an endpoint docks with. |
| Dock | One admitted connection of an endpoint to an edge. |
| Generation | The identity of one dock. Naming it on the next dock makes that dock a succession. |
| Lane | An association, established by the fabric, between a dock and another endpoint. It carries streams. |
| Zone | An independent deployment of the fabric with its own trust domain. |
| Plane | One of the fabrics in a zone: the control plane or the data plane. |
| Admission lease | The signed statement of what an endpoint is admitted as. |
| Trust snapshot | The set of certificate authorities a zone trusts for one purpose. |

## Status

The API is not yet stable. Package names and exported identifiers may change
before the first tagged release.

## Requirements

Go 1.26.6 or later. The module depends on
[quic-go](https://github.com/quic-go/quic-go),
[go-spiffe](https://github.com/spiffe/go-spiffe),
[golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) and the Go
protobuf runtime.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities as described in
[SECURITY.md](SECURITY.md), never in a public issue.

## License

Apache License 2.0. See [LICENSE](LICENSE).
