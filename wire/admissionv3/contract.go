// Copyright 2026 Idyl Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package admissionv3 defines the zone-admission-lease/3 contract: the
// signed ZoneAdmissionLease envelope and its canonical payload, the
// DockProofInput a client signs to bind a lease to one dock connection,
// and the constants and bounds both sides of the contract share.
//
// Leases are signed by X.509-SVID admission signers with ECDSA
// P-256/SHA-256 in strict low-S DER. The signer chain is leaf first and is
// validated against the verifier's current local trust bundle and one
// exact expected signer URI per fabric plane.
//
// # Principal grammar
//
// Every lease binds to a connection SVID carrying exactly one URI SAN in
// the zone trust domain. The URI path depends on the endpoint kind:
//
//	node:    /subnet/{subnet}/node/{nodeID}
//	pod:     /subnet/{subnet}/account/{account}/namespace/{namespaceID}/workload/{workloadID}/pod-name/{podName}/pod/{podID}
//	session: /subnet/{subnet}/account/{account}/namespace/{namespaceID}/workload/{workloadID}/pod/{podID}/pod-instance/{podID}.{generation}/session/{kind}/{sessionID}/leg/{leg}
//	session: /subnet/{subnet}/account/{account}/namespace/{namespaceID}/workload/{workloadID}/pod/{podID}/pod-instance/{podID}.{generation}/micropod/{sequence}/session/{kind}/{sessionID}/leg/{leg}
//	share:   /share/{shareID}
//
// Every keyword segment is compared byte for byte at its own index, and
// every value segment is compared to the lease field carrying the same
// fact. The segment count is checked before any value is read, so a path
// of any other shape is refused outright; there is no alternative
// decoding.
//
// In a pod principal, {podID} is the authoritative runtime pod identity;
// {podName} is diagnostic, must be present, and is never authority on its
// own. A share lease names the data plane and carries no subnet, account,
// namespace, workload, node or pod fact.
//
// A session lease selects one of the two session paths by its
// micropod_sequence. Zero selects the first, seventeen-segment path: the
// session targets the Pod itself. A positive value selects the second,
// nineteen-segment path, a session that targets one Micropod within the
// Pod, and {sequence} is that value in decimal, with no sign and no leading
// zero. Only exec and shell sessions may target a Micropod. A principal of
// one path never matches a lease that selects the other, and no other
// spelling of the sequence matches.
package admissionv3

import "time"

// Contract identifiers, signature domains, and the bounds every encoder and
// verifier of this contract enforces.
const (
	// ZoneAdmissionLeaseContract is the contract string carried in every
	// ZoneAdmissionLease envelope.
	ZoneAdmissionLeaseContract = "zone-admission-lease/3"

	// Signature domains are byte prefixes. Signers and verifiers append a
	// four-byte big-endian input length and the exact canonical input bytes.
	// The lease domain names this contract version, so a signature made
	// under any other lease contract never verifies here.
	ZoneAdmissionLeaseSignatureDomain = "idyl-zone-admission-lease-signature/v3\x00"
	DockProofSignatureDomain          = "idyl-dock-proof-signature/v1\x00"

	// DockContract is the dock protocol a dock proof binds to.
	DockContract = "dock/3"
	// TLSExporterLabel is the TLS exporter label (RFC 5705, RFC 8446) for
	// the keying material that binds a dock proof to its connection.
	TLSExporterLabel = "EXPORTER-IDYL-DOCK-PROOF-v1"

	PayloadVersion   = 3
	DockProofVersion = 1
	// IssuerBackdate is the exact distance between a lease's not_before
	// and its issued_at: issued_at always equals not_before plus
	// IssuerBackdate, so a verifier whose clock runs slightly behind the
	// issuer's still accepts a freshly issued lease.
	IssuerBackdate = 60 * time.Second
	// VerifierClockGrace is the extra tolerance a verifier applies to the
	// validity interval. It is zero: verifiers apply the signed interval
	// exactly.
	VerifierClockGrace = 0 * time.Second

	MaxLeaseEnvelopeBytes   = 16 * 1024
	MaxLeasePayloadBytes    = 4 * 1024
	MaxSignerCertificateDER = 4 * 1024
	// The signer chain carries the X.509-SVID admission signer leaf first,
	// followed by any intermediates up to, and excluding, the verifier's
	// trust anchors. Chain length, per-certificate DER size, and aggregate
	// DER size are all bounded.
	MaxSignerChainLength   = 4
	MaxSignerChainDERBytes = 12 * 1024
	MaxDockProofInputBytes = 1024

	LeaseIDBytes             = 16
	SHA256Bytes              = 32
	TLSExporterBytes         = 32
	DockGenerationNonceBytes = 12

	// Lease signatures are ECDSA P-256/SHA-256 in strict ASN.1 DER with a
	// canonical low-S value. Dock proofs are fixed-width Ed25519 signatures
	// made with the endpoint's own SVID key; the two bounds are separate
	// because the algorithms differ.
	MinLeaseSignatureBytes  = 8
	MaxLeaseSignatureBytes  = 72
	DockProofSignatureBytes = 64

	MaxZoneBytes          = 63
	MaxPrincipalBytes     = 1024
	MaxIdentifierBytes    = 255
	MaxPolicyProfileBytes = 64

	// MaxMicropodSequence is the largest Micropod sequence number a session
	// lease or mint request may carry, 2^53-1, so that every sequence is
	// exact wherever it is carried as a JSON number.
	MaxMicropodSequence = 1<<53 - 1

	// MaxAdmissionSignerLifetime caps the signer leaf's encoded validity
	// interval. Issuance policy requests shorter-lived signers; the cap is
	// enforced at verification so an out-of-profile signer cannot be used
	// regardless of how it was issued.
	MaxAdmissionSignerLifetime = 24 * time.Hour

	// Maximum signed lease intervals per endpoint kind. A node lease is
	// bounded from not_before; session and share leases are bounded from
	// issued_at.
	MaxNodeLeaseLifetime    = 24 * time.Hour
	MaxSessionLeaseLifetime = 60 * time.Minute
	MaxShareLeaseLifetime   = 60 * time.Minute
)

// Admission signer SPIFFE ID paths. An admission signer must present the
// path for the plane its lease admits: ControlPlaneAdmissionSignerPath for
// the control plane and DataPlaneAdmissionSignerPath for the data plane.
// Exactly one identity may sign for each plane. Verifiers derive the full
// URI from the zone trust domain and the plane, never from lease content,
// and compare it byte for byte.
const (
	ControlPlaneAdmissionSignerPath = "/service/join/admission-issuer"
	DataPlaneAdmissionSignerPath    = "/service/controller/admission-issuer"
)
