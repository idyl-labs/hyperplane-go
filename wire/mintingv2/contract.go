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

// Package mintingv2 defines the credential mint records for pods and
// sessions, with validators for each record.
//
// A mint is atomic: a successful reply carries the X.509-SVID chain, the
// exact ZoneAdmissionLease envelope that admits it, and the trust snapshot
// its issuer belongs to, together. A reply that carries a certificate
// without its lease cannot be represented. A refused mint carries only a
// short refusal code.
//
// Every validator refuses a record that carries unknown protobuf fields.
package mintingv2

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	"github.com/idyl-labs/hyperplane-go/wire/commonv2"
	"github.com/idyl-labs/hyperplane-go/wire/trustv1"
)

// Envelope type names for the mint records, and the size bounds every
// validator in this package enforces.
const (
	EnvelopeTypeMintPodSvid          = "mint_pod_svid_v2_request"
	EnvelopeTypeMintPodSvidReply     = "mint_pod_svid_v2_response"
	EnvelopeTypeMintSessionSvid      = "mint_session_svid_request"
	EnvelopeTypeMintSessionSvidReply = "mint_session_svid_response"

	MaxCSRDERBytes         = 16 * 1024
	MaxCertificateDERBytes = 16 * 1024
	MaxCertificateChain    = 4
	MaxRefusalCodeBytes    = 64
)

// Carrier preserves a record's canonical bytes inside an outer JSON
// envelope on the control dock, so the record is never decoded and
// re-encoded in transit. It has no field other than the record.
type Carrier struct {
	Record []byte `json:"record"`
}

// ValidateMintPodSvidRequest checks a pod mint request: a bounded CSR, a
// pod ID, a positive assignment generation, and nothing else. A request
// carries only public material; the private key never leaves the
// requester.
func ValidateMintPodSvidRequest(request *MintPodSvidRequest) error {
	if request == nil || len(request.GetCsrDer()) == 0 || len(request.GetCsrDer()) > MaxCSRDERBytes ||
		!validText(request.GetPodId(), admissionv3.MaxIdentifierBytes) || request.GetAssignmentGeneration() <= 0 {
		return fmt.Errorf("mintingv2: invalid pod mint request")
	}
	return rejectUnknown(request)
}

// ValidateMintSessionSvidRequest checks a session mint request: one
// bounded CSR, the session and pod binding facts, an expiry, a known
// session kind and leg, a grant_id that is present on the proxy leg and
// absent on the client leg, and a micropod_sequence that is zero or, for
// an exec or shell session only, at most admissionv3.MaxMicropodSequence.
func ValidateMintSessionSvidRequest(request *MintSessionSvidRequest) error {
	if request == nil || len(request.GetCsrDer()) == 0 || len(request.GetCsrDer()) > MaxCSRDERBytes ||
		!validText(request.GetSessionId(), admissionv3.MaxIdentifierBytes) ||
		!validText(request.GetPodId(), admissionv3.MaxIdentifierBytes) ||
		request.GetAssignmentGeneration() <= 0 || request.GetExpiresAtUnixS() == 0 {
		return fmt.Errorf("mintingv2: invalid session mint request")
	}
	switch request.GetSessionKind() {
	case commonv2.SessionKind_SESSION_KIND_EXEC,
		commonv2.SessionKind_SESSION_KIND_LOGS,
		commonv2.SessionKind_SESSION_KIND_SHELL:
	default:
		return fmt.Errorf("mintingv2: unknown session kind %d", request.GetSessionKind())
	}
	switch request.GetSessionLeg() {
	case commonv2.SessionLeg_SESSION_LEG_CLIENT:
		if request.GetGrantId() != "" {
			return fmt.Errorf("mintingv2: client session leg carries proxy grant")
		}
	case commonv2.SessionLeg_SESSION_LEG_PROXY:
		if !validText(request.GetGrantId(), admissionv3.MaxIdentifierBytes) {
			return fmt.Errorf("mintingv2: proxy session leg requires grant")
		}
	default:
		return fmt.Errorf("mintingv2: unknown session leg %d", request.GetSessionLeg())
	}
	if sequence := request.GetMicropodSequence(); sequence != 0 {
		if sequence > admissionv3.MaxMicropodSequence {
			return fmt.Errorf("mintingv2: micropod sequence exceeds %d", uint64(admissionv3.MaxMicropodSequence))
		}
		if request.GetSessionKind() != commonv2.SessionKind_SESSION_KIND_EXEC && request.GetSessionKind() != commonv2.SessionKind_SESSION_KIND_SHELL {
			return fmt.Errorf("mintingv2: micropod session kind %d", request.GetSessionKind())
		}
	}
	return rejectUnknown(request)
}

// ValidatePodCredentialGeneration checks a successful pod mint: a bounded
// certificate chain and lease envelope, a renewal instant strictly inside
// the credential interval [notBeforeUnixS, notAfterUnixS], and a POD trust
// snapshot under which the leaf verifies.
func ValidatePodCredentialGeneration(generation *PodCredentialGeneration, notBeforeUnixS, notAfterUnixS uint64) error {
	if generation == nil {
		return fmt.Errorf("mintingv2: pod credential generation absent")
	}
	if err := validateChainAndLease(generation.GetCertDer(), generation.GetLeaseEnvelope()); err != nil {
		return err
	}
	if generation.GetRenewAtUnixS() <= notBeforeUnixS || generation.GetRenewAtUnixS() >= notAfterUnixS {
		return fmt.Errorf("mintingv2: renewal instant is outside credential interval")
	}
	if err := validatePodTrustPair(generation.GetCertDer(), generation.GetTrustSnapshot()); err != nil {
		return err
	}
	return rejectUnknown(generation)
}

func validatePodTrustPair(chainDER [][]byte, snapshot *trustv1.TrustSnapshot) error {
	if err := validateCredentialTrustPair(chainDER, snapshot); err != nil {
		return fmt.Errorf("mintingv2: pod trust snapshot: %w", err)
	}
	return nil
}

func validateCredentialTrustPair(chainDER [][]byte, snapshot *trustv1.TrustSnapshot) error {
	if len(chainDER) == 0 {
		return fmt.Errorf("credential chain absent")
	}
	leaf, err := x509.ParseCertificate(chainDER[0])
	if err != nil {
		return fmt.Errorf("credential leaf: %w", err)
	}
	if snapshot == nil {
		return fmt.Errorf("trust snapshot absent")
	}
	// Leaves are backdated to absorb bounded clock skew, so leaf.NotBefore
	// can precede the snapshot's issue instant even when the snapshot was
	// published first. A leaf can also be minted while an older snapshot is
	// still current. The first instant at which both objects can be valid is
	// therefore the later of the two timestamps. Validating and verifying at
	// that instant accepts both legitimate shapes and refuses a snapshot
	// published after the leaf expired.
	pairingTime := leaf.NotBefore.UTC()
	snapshotIssuedAt := time.Unix(snapshot.GetIssuedAtUnixS(), 0).UTC()
	if snapshotIssuedAt.After(pairingTime) {
		pairingTime = snapshotIssuedAt
	}
	if err := trustv1.ValidateTrustSnapshotAt(snapshot, pairingTime); err != nil {
		return err
	}
	if snapshot.GetPurpose() != trustv1.Purpose_PURPOSE_POD {
		return fmt.Errorf("credential carries non-POD trust snapshot")
	}
	roots := x509.NewCertPool()
	for _, generation := range snapshot.GetGenerations() {
		certificate, err := x509.ParseCertificate(generation.GetCertificateDer())
		if err != nil {
			return fmt.Errorf("trust generation: %w", err)
		}
		roots.AddCert(certificate)
	}
	intermediates := x509.NewCertPool()
	for index, certificateDER := range chainDER[1:] {
		certificate, err := x509.ParseCertificate(certificateDER)
		if err != nil {
			return fmt.Errorf("credential intermediate %d: %w", index, err)
		}
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   pairingTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("credential issuer absent from paired POD snapshot: %w", err)
	}
	return nil
}

// ValidateSessionCredentialGeneration checks a successful session mint: a
// bounded certificate chain and lease envelope, and a POD trust snapshot
// under which the leaf verifies.
func ValidateSessionCredentialGeneration(generation *SessionCredentialGeneration) error {
	if generation == nil {
		return fmt.Errorf("mintingv2: session credential generation absent")
	}
	if err := validateChainAndLease(generation.GetCertDer(), generation.GetLeaseEnvelope()); err != nil {
		return err
	}
	if err := validateCredentialTrustPair(generation.GetCertDer(), generation.GetTrustSnapshot()); err != nil {
		return fmt.Errorf("mintingv2: session trust snapshot: %w", err)
	}
	return rejectUnknown(generation)
}

// ValidateMintPodSvidReply checks a pod mint reply, which carries exactly
// one verdict: a credential generation, validated as by
// ValidatePodCredentialGeneration, or a refusal whose code is lowercase
// letters and hyphens.
func ValidateMintPodSvidReply(reply *MintPodSvidReply, notBeforeUnixS, notAfterUnixS uint64) error {
	if reply == nil {
		return fmt.Errorf("mintingv2: pod mint reply absent")
	}
	if err := rejectUnknown(reply); err != nil {
		return err
	}
	switch verdict := reply.GetVerdict().(type) {
	case *MintPodSvidReply_Generation:
		return ValidatePodCredentialGeneration(verdict.Generation, notBeforeUnixS, notAfterUnixS)
	case *MintPodSvidReply_Refusal:
		return validateRefusal(verdict.Refusal)
	default:
		return fmt.Errorf("mintingv2: pod mint reply has no verdict")
	}
}

// ValidateMintSessionSvidReply checks a session mint reply, which carries
// exactly one verdict: a credential generation, validated as by
// ValidateSessionCredentialGeneration, or a refusal.
func ValidateMintSessionSvidReply(reply *MintSessionSvidReply) error {
	if reply == nil {
		return fmt.Errorf("mintingv2: session mint reply absent")
	}
	if err := rejectUnknown(reply); err != nil {
		return err
	}
	switch verdict := reply.GetVerdict().(type) {
	case *MintSessionSvidReply_Generation:
		return ValidateSessionCredentialGeneration(verdict.Generation)
	case *MintSessionSvidReply_Refusal:
		return validateRefusal(verdict.Refusal)
	default:
		return fmt.Errorf("mintingv2: session mint reply has no verdict")
	}
}

func validateChainAndLease(chain [][]byte, lease []byte) error {
	if len(chain) == 0 || len(chain) > MaxCertificateChain {
		return fmt.Errorf("mintingv2: certificate chain length %d", len(chain))
	}
	for i, cert := range chain {
		if len(cert) == 0 || len(cert) > MaxCertificateDERBytes {
			return fmt.Errorf("mintingv2: certificate %d size %d", i, len(cert))
		}
	}
	if len(lease) == 0 || len(lease) > admissionv3.MaxLeaseEnvelopeBytes {
		return fmt.Errorf("mintingv2: lease envelope size %d", len(lease))
	}
	return nil
}

func validateRefusal(refusal *Refusal) error {
	if refusal == nil || !validText(refusal.GetCode(), MaxRefusalCodeBytes) {
		return fmt.Errorf("mintingv2: invalid refusal")
	}
	for _, r := range refusal.GetCode() {
		if (r < 'a' || r > 'z') && r != '-' {
			return fmt.Errorf("mintingv2: invalid refusal code")
		}
	}
	return rejectUnknown(refusal)
}

func validText(value string, max int) bool {
	return value != "" && len(value) <= max && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsRune(value, '\x00')
}

func rejectUnknown(message proto.Message) error {
	if len(message.ProtoReflect().GetUnknown()) != 0 {
		return fmt.Errorf("mintingv2: unknown content")
	}
	return nil
}
