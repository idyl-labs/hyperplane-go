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

package wire

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	apb "github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	mpb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
	dockpb "github.com/idyl-labs/hyperplane-go/wire/dockv3"
)

const (
	knownAdapterClasses uint64 = (1 << 7) - 1
	knownLaneClasses           = LaneClassStream | LaneClassFlow | LaneClassIngressTarget | LaneClassSpliceLeg

	// podPrincipalSegments is the exact path segment count of a pod
	// connection SVID: subnet, account, namespace, workload,
	// pod-name, and pod, each a keyword followed by its value. The count
	// identifies the path shape and is checked before any value is read.
	podPrincipalSegments     = 12
	sessionPrincipalSegments = 17
	sharePrincipalSegments   = 2
)

// Admission refusal classes. The lease, payload, binding and dock proof
// functions in this package wrap these errors; classify a refusal with
// errors.Is, never by its text.
var (
	ErrAdmissionMalformed    = errors.New("wire: admission record malformed")
	ErrAdmissionNonCanonical = errors.New("wire: admission record is not canonical")
	ErrAdmissionExpired      = errors.New("wire: admission lease expired")
	ErrAdmissionNotYetValid  = errors.New("wire: admission lease not yet valid")
	ErrAdmissionBinding      = errors.New("wire: admission lease does not match authenticated peer")
	ErrAdmissionSignature    = errors.New("wire: admission signature invalid")
	// ErrAdmissionUnsupportedContract names an envelope whose contract tag is
	// not zone-admission-lease/3, the one supported admission contract. Any
	// other contract tag fails with this error by name; nothing decodes,
	// upgrades, or translates such an envelope.
	ErrAdmissionUnsupportedContract = errors.New("wire: unsupported admission lease contract")
)

// LeasePeer is the authenticated SVID context against which a parsed lease is
// matched. Session callers must supply GrantNotAfterUnixS; pod, session and
// share leases end exactly with their SVID, while a node lease may end earlier.
type LeasePeer struct {
	Principal           string
	SubjectSPKISHA256   []byte
	Zone                string
	FabricPlane         mpb.Plane
	EndpointKind        mpb.EndpointKind
	SVIDNotAfterUnixS   uint64
	SignerNotAfterUnixS uint64
	GrantNotAfterUnixS  uint64
}

// MarshalZoneAdmissionLeasePayload validates and canonically serializes one
// freshly built payload. Its issued_at instant is the validation clock.
func MarshalZoneAdmissionLeasePayload(payload *apb.ZoneAdmissionLeasePayload) ([]byte, error) {
	if payload == nil {
		return nil, fmt.Errorf("%w: lease payload absent", ErrAdmissionMalformed)
	}
	if err := ValidateZoneAdmissionLeasePayload(payload, payload.GetIssuedAtUnixS()); err != nil {
		return nil, err
	}
	raw, err := MarshalCanonical(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrAdmissionMalformed, err)
	}
	if len(raw) > apb.MaxLeasePayloadBytes {
		return nil, fmt.Errorf("%w: payload is %d bytes, maximum %d", ErrAdmissionMalformed, len(raw), apb.MaxLeasePayloadBytes)
	}
	return raw, nil
}

// MarshalZoneAdmissionLease canonically serializes a structurally complete
// signed envelope. It does not validate the signer chain or signature; those
// judgments require the caller's current trust bundle.
func MarshalZoneAdmissionLease(envelope *apb.ZoneAdmissionLease) ([]byte, error) {
	if err := validateZoneAdmissionLeaseEnvelope(envelope); err != nil {
		return nil, err
	}
	var payload apb.ZoneAdmissionLeasePayload
	if err := unmarshalCanonical(envelope.GetPayload(), &payload, apb.MaxLeasePayloadBytes, "lease payload"); err != nil {
		return nil, err
	}
	if err := ValidateZoneAdmissionLeasePayload(&payload, payload.GetIssuedAtUnixS()); err != nil {
		return nil, err
	}
	raw, err := MarshalCanonical(envelope)
	if err != nil {
		return nil, fmt.Errorf("%w: envelope: %v", ErrAdmissionMalformed, err)
	}
	if len(raw) > apb.MaxLeaseEnvelopeBytes {
		return nil, fmt.Errorf("%w: lease envelope is %d bytes, maximum %d", ErrAdmissionMalformed, len(raw), apb.MaxLeaseEnvelopeBytes)
	}
	return raw, nil
}

// ParseZoneAdmissionLease parses exact canonical envelope and payload bytes,
// enforces every size/profile/time rule, and retains the raw payload on the
// envelope for signature verification. Unknown or non-minimal encodings fail.
func ParseZoneAdmissionLease(raw []byte, nowUnixS uint64) (*apb.ZoneAdmissionLease, *apb.ZoneAdmissionLeasePayload, error) {
	var envelope apb.ZoneAdmissionLease
	if err := unmarshalCanonical(raw, &envelope, apb.MaxLeaseEnvelopeBytes, "lease envelope"); err != nil {
		return nil, nil, err
	}
	if err := validateZoneAdmissionLeaseEnvelope(&envelope); err != nil {
		return nil, nil, err
	}
	var payload apb.ZoneAdmissionLeasePayload
	if err := unmarshalCanonical(envelope.GetPayload(), &payload, apb.MaxLeasePayloadBytes, "lease payload"); err != nil {
		return nil, nil, err
	}
	if err := ValidateZoneAdmissionLeasePayload(&payload, nowUnixS); err != nil {
		return nil, nil, err
	}
	return &envelope, &payload, nil
}

func validateZoneAdmissionLeaseEnvelope(envelope *apb.ZoneAdmissionLease) error {
	if envelope == nil {
		return fmt.Errorf("%w: lease envelope absent", ErrAdmissionMalformed)
	}
	if err := rejectUnknown(envelope.ProtoReflect()); err != nil {
		return fmt.Errorf("%w: envelope unknown content: %v", ErrAdmissionMalformed, err)
	}
	if envelope.GetContract() != apb.ZoneAdmissionLeaseContract {
		return fmt.Errorf("%w: %q", ErrAdmissionUnsupportedContract, envelope.GetContract())
	}
	if len(envelope.GetPayload()) == 0 || len(envelope.GetPayload()) > apb.MaxLeasePayloadBytes {
		return fmt.Errorf("%w: lease payload size %d", ErrAdmissionMalformed, len(envelope.GetPayload()))
	}
	if _, _, err := ParseLeaseSignature(envelope.GetSignature()); err != nil {
		return fmt.Errorf("%w: %v", ErrAdmissionMalformed, err)
	}
	if len(envelope.GetSignerKeyId()) != apb.SHA256Bytes {
		return fmt.Errorf("%w: signer key id size %d", ErrAdmissionMalformed, len(envelope.GetSignerKeyId()))
	}
	chain := envelope.GetSignerCertChain()
	if len(chain) == 0 || len(chain) > apb.MaxSignerChainLength {
		return fmt.Errorf("%w: signer chain length %d", ErrAdmissionMalformed, len(chain))
	}
	total := 0
	for i, cert := range chain {
		if len(cert) == 0 || len(cert) > apb.MaxSignerCertificateDER {
			return fmt.Errorf("%w: signer certificate %d size %d", ErrAdmissionMalformed, i, len(cert))
		}
		total += len(cert)
	}
	if total > apb.MaxSignerChainDERBytes {
		return fmt.Errorf("%w: signer chain aggregate size %d", ErrAdmissionMalformed, total)
	}
	return nil
}

// ZoneAdmissionLeaseSignatureInput is the exact lease signature input: the
// fixed lease signature domain, a four-byte big-endian length, then the
// transmitted canonical payload bytes. The signer hashes this input with SHA-256 and signs with
// ECDSA P-256, producing canonical low-S DER.
func ZoneAdmissionLeaseSignatureInput(payload []byte) []byte {
	return domainSeparated(apb.ZoneAdmissionLeaseSignatureDomain, payload)
}

// VerifyZoneAdmissionLeaseSignature verifies the raw payload without
// reconstructing it. Signer-chain validation and key-id/SPKI matching precede
// this call at the trust boundary.
func VerifyZoneAdmissionLeaseSignature(envelope *apb.ZoneAdmissionLease, publicKey *ecdsa.PublicKey) error {
	if err := validateZoneAdmissionLeaseEnvelope(envelope); err != nil {
		return err
	}
	return verifyLeaseSignatureP256(publicKey, envelope.GetPayload(), envelope.GetSignature())
}

// ValidateZoneAdmissionLeasePayload enforces the closed payload vocabulary,
// bounded strings/masks, exact kind profiles, incarnation shape, fixed
// 60-second issuer backdate, and zero verifier grace. Validity is
// not_before <= now < not_after.
func ValidateZoneAdmissionLeasePayload(payload *apb.ZoneAdmissionLeasePayload, nowUnixS uint64) error {
	if payload == nil {
		return fmt.Errorf("%w: lease payload absent", ErrAdmissionMalformed)
	}
	if err := rejectUnknown(payload.ProtoReflect()); err != nil {
		return fmt.Errorf("%w: payload unknown content: %v", ErrAdmissionMalformed, err)
	}
	if payload.GetVersion() != apb.PayloadVersion {
		return fmt.Errorf("%w: lease payload version %d", ErrAdmissionMalformed, payload.GetVersion())
	}
	if len(payload.GetLeaseId()) != apb.LeaseIDBytes {
		return fmt.Errorf("%w: lease id size %d", ErrAdmissionMalformed, len(payload.GetLeaseId()))
	}
	if err := boundedText("zone", payload.GetZone(), apb.MaxZoneBytes); err != nil {
		return err
	}
	if !isDNSLabel(payload.GetZone()) {
		return fmt.Errorf("%w: zone is not a lowercase DNS label", ErrAdmissionMalformed)
	}
	if payload.GetFabricPlane() != mpb.Plane_PLANE_CONTROL && payload.GetFabricPlane() != mpb.Plane_PLANE_DATA {
		return fmt.Errorf("%w: unknown fabric plane %d", ErrAdmissionMalformed, payload.GetFabricPlane())
	}
	if err := boundedText("principal", payload.GetPrincipal(), apb.MaxPrincipalBytes); err != nil {
		return err
	}
	if len(payload.GetSubjectSpkiSha256()) != apb.SHA256Bytes {
		return fmt.Errorf("%w: subject SPKI digest size %d", ErrAdmissionMalformed, len(payload.GetSubjectSpkiSha256()))
	}
	if payload.GetEndpointKind() != mpb.EndpointKind_ENDPOINT_KIND_NODE &&
		payload.GetEndpointKind() != mpb.EndpointKind_ENDPOINT_KIND_POD &&
		payload.GetEndpointKind() != mpb.EndpointKind_ENDPOINT_KIND_SESSION &&
		payload.GetEndpointKind() != mpb.EndpointKind_ENDPOINT_KIND_SHARE {
		return fmt.Errorf("%w: unknown dynamic endpoint kind %d", ErrAdmissionMalformed, payload.GetEndpointKind())
	}
	for name, value := range map[string]string{
		"subnet_id": payload.GetSubnetId(), "owner_scope": payload.GetOwnerScope(),
		"account_id": payload.GetAccountId(), "namespace_id": payload.GetNamespaceId(),
		"workload_id": payload.GetWorkloadId(), "node_id": payload.GetNodeId(),
		"pod_id": payload.GetPodId(), "pod_instance_id": payload.GetPodInstanceId(),
		"session_id": payload.GetSessionId(), "grant_id": payload.GetGrantId(),
		"share_id": payload.GetShareId(),
	} {
		if value != "" {
			if err := boundedText(name, value, apb.MaxIdentifierBytes); err != nil {
				return err
			}
		}
	}
	if payload.GetNamespaceId() != "" && !isCanonicalUUID(payload.GetNamespaceId()) {
		return fmt.Errorf("%w: namespace_id is not a canonical lowercase UUID", ErrAdmissionMalformed)
	}
	if payload.GetAdapterClasses() == 0 || payload.GetAdapterClasses()&^knownAdapterClasses != 0 {
		return fmt.Errorf("%w: invalid adapter class mask %#x", ErrAdmissionMalformed, payload.GetAdapterClasses())
	}
	if payload.GetLaneClassCeiling()&^knownLaneClasses != 0 || payload.GetLaneClassCeiling()&^payload.GetAdapterClasses() != 0 {
		return fmt.Errorf("%w: invalid lane class ceiling %#x", ErrAdmissionMalformed, payload.GetLaneClassCeiling())
	}
	if err := boundedText("policy_profile", payload.GetPolicyProfile(), apb.MaxPolicyProfileBytes); err != nil {
		return err
	}
	if payload.GetPolicyProfileVersion() == 0 {
		return fmt.Errorf("%w: policy profile version is zero", ErrAdmissionMalformed)
	}
	if payload.GetNotBeforeUnixS() == 0 || payload.GetIssuedAtUnixS() == 0 || payload.GetNotAfterUnixS() == 0 {
		return fmt.Errorf("%w: lease time is zero", ErrAdmissionMalformed)
	}
	backdate := uint64(apb.IssuerBackdate.Seconds())
	if payload.GetNotBeforeUnixS() > ^uint64(0)-backdate || payload.GetNotBeforeUnixS()+backdate != payload.GetIssuedAtUnixS() {
		return fmt.Errorf("%w: issued_at must equal not_before plus %s", ErrAdmissionMalformed, apb.IssuerBackdate)
	}
	if payload.GetIssuedAtUnixS() >= payload.GetNotAfterUnixS() {
		return fmt.Errorf("%w: issued_at must precede not_after", ErrAdmissionMalformed)
	}
	if nowUnixS < payload.GetNotBeforeUnixS() {
		return ErrAdmissionNotYetValid
	}
	if nowUnixS >= payload.GetNotAfterUnixS() {
		return ErrAdmissionExpired
	}

	principal, err := parseAdmissionPrincipal(payload.GetPrincipal(), payload.GetZone())
	if err != nil {
		return err
	}
	switch payload.GetEndpointKind() {
	case mpb.EndpointKind_ENDPOINT_KIND_NODE:
		if err := validateNodeLeaseProfile(payload, principal); err != nil {
			return err
		}
		if payload.GetNotAfterUnixS()-payload.GetNotBeforeUnixS() > uint64(apb.MaxNodeLeaseLifetime.Seconds()) {
			return fmt.Errorf("%w: node signed interval exceeds %s", ErrAdmissionMalformed, apb.MaxNodeLeaseLifetime)
		}
	case mpb.EndpointKind_ENDPOINT_KIND_POD:
		if err := validatePodLeaseProfile(payload, principal); err != nil {
			return err
		}
	case mpb.EndpointKind_ENDPOINT_KIND_SESSION:
		if err := validateSessionLeaseProfile(payload, principal); err != nil {
			return err
		}
		if payload.GetNotAfterUnixS()-payload.GetIssuedAtUnixS() > uint64(apb.MaxSessionLeaseLifetime.Seconds()) {
			return fmt.Errorf("%w: session grant interval exceeds %s", ErrAdmissionMalformed, apb.MaxSessionLeaseLifetime)
		}
	case mpb.EndpointKind_ENDPOINT_KIND_SHARE:
		if err := validateShareLeaseProfile(payload, principal); err != nil {
			return err
		}
		if payload.GetNotAfterUnixS()-payload.GetIssuedAtUnixS() > uint64(apb.MaxShareLeaseLifetime.Seconds()) {
			return fmt.Errorf("%w: share interval exceeds %s", ErrAdmissionMalformed, apb.MaxShareLeaseLifetime)
		}
	}
	return nil
}

// ValidateZoneAdmissionLeaseBinding matches a structurally valid payload to
// the exact authenticated peer and its certificate/signer/grant deadlines.
func ValidateZoneAdmissionLeaseBinding(payload *apb.ZoneAdmissionLeasePayload, peer LeasePeer) error {
	if payload == nil {
		return fmt.Errorf("%w: nil payload", ErrAdmissionBinding)
	}
	if payload.GetPrincipal() != peer.Principal ||
		!bytes.Equal(payload.GetSubjectSpkiSha256(), peer.SubjectSPKISHA256) ||
		payload.GetZone() != peer.Zone || payload.GetFabricPlane() != peer.FabricPlane ||
		payload.GetEndpointKind() != peer.EndpointKind {
		return ErrAdmissionBinding
	}
	if peer.SVIDNotAfterUnixS == 0 || payload.GetNotAfterUnixS() > peer.SVIDNotAfterUnixS {
		return fmt.Errorf("%w: lease outlives SVID", ErrAdmissionBinding)
	}
	if peer.SignerNotAfterUnixS != 0 && payload.GetNotAfterUnixS() > peer.SignerNotAfterUnixS {
		return fmt.Errorf("%w: lease outlives signer", ErrAdmissionBinding)
	}
	if payload.GetEndpointKind() == mpb.EndpointKind_ENDPOINT_KIND_POD || payload.GetEndpointKind() == mpb.EndpointKind_ENDPOINT_KIND_SESSION ||
		payload.GetEndpointKind() == mpb.EndpointKind_ENDPOINT_KIND_SHARE {
		if payload.GetNotAfterUnixS() != peer.SVIDNotAfterUnixS {
			return fmt.Errorf("%w: pod/session/share lease deadline differs from SVID", ErrAdmissionBinding)
		}
	}
	if payload.GetEndpointKind() == mpb.EndpointKind_ENDPOINT_KIND_SESSION {
		if peer.GrantNotAfterUnixS == 0 || payload.GetNotAfterUnixS() != peer.GrantNotAfterUnixS {
			return fmt.Errorf("%w: session lease deadline differs from grant", ErrAdmissionBinding)
		}
	}
	return nil
}

type admissionPrincipal struct {
	segments []string
}

func parseAdmissionPrincipal(raw, zone string) (admissionPrincipal, error) {
	u, err := url.Parse(raw)
	if err != nil || u.String() != raw {
		return admissionPrincipal{}, fmt.Errorf("%w: malformed authenticated principal", ErrAdmissionMalformed)
	}
	if u.Scheme != "spiffe" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Port() != "" || u.RawPath != "" {
		return admissionPrincipal{}, fmt.Errorf("%w: malformed SPIFFE principal", ErrAdmissionMalformed)
	}
	prefix := zone + ".zone."
	if !strings.HasPrefix(u.Host, prefix) || len(u.Host) == len(prefix) || u.String() != raw {
		return admissionPrincipal{}, fmt.Errorf("%w: principal trust domain does not match zone", ErrAdmissionMalformed)
	}
	if !strings.HasPrefix(u.Path, "/") || strings.HasSuffix(u.Path, "/") {
		return admissionPrincipal{}, fmt.Errorf("%w: malformed principal path", ErrAdmissionMalformed)
	}
	segments := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	for _, segment := range segments {
		if segment == "" || strings.TrimSpace(segment) != segment {
			return admissionPrincipal{}, fmt.Errorf("%w: malformed principal segment", ErrAdmissionMalformed)
		}
	}
	return admissionPrincipal{segments: segments}, nil
}

func validateNodeLeaseProfile(p *apb.ZoneAdmissionLeasePayload, principal admissionPrincipal) error {
	if err := requireText(p.GetSubnetId(), "subnet_id"); err != nil {
		return err
	}
	if err := requireText(p.GetOwnerScope(), "owner_scope"); err != nil {
		return err
	}
	if err := requireText(p.GetNodeId(), "node_id"); err != nil {
		return err
	}
	// NODE_ADMISSION_PROVIDER names the provider-admission type. It covers
	// nodes admitted directly and nodes admitted through an active provider
	// fleet.
	if p.GetNodeAdmission() != apb.NodeAdmission_NODE_ADMISSION_PROVIDER {
		return fmt.Errorf("%w: node provider admission fact absent", ErrAdmissionMalformed)
	}
	if p.GetAccountId() != "" || p.GetNamespaceId() != "" || p.GetWorkloadId() != "" ||
		p.GetPodId() != "" || p.GetPodInstanceId() != "" || p.GetAssignmentGeneration() != 0 || p.GetSessionId() != "" ||
		p.GetSessionKind() != mpb.SessionKind_SESSION_KIND_UNSPECIFIED || p.GetSessionLeg() != mpb.SessionLeg_SESSION_LEG_UNSPECIFIED || p.GetGrantId() != "" ||
		p.GetShareId() != "" {
		return fmt.Errorf("%w: node lease carries fields from another kind", ErrAdmissionMalformed)
	}
	if len(principal.segments) != 4 || principal.segments[0] != "subnet" || principal.segments[1] != p.GetSubnetId() ||
		principal.segments[2] != "node" || principal.segments[3] != p.GetNodeId() {
		return fmt.Errorf("%w: node principal does not match lease", ErrAdmissionMalformed)
	}
	return nil
}

// validatePodLeaseProfile enforces the pod leg: every pod identity fact
// present, the pod incarnation encoding, no field belonging to another
// endpoint kind, and byte-exact agreement between the payload and all
// twelve segments of the bound pod principal. Account and stable Namespace ID
// are both required and byte-match their principal segments.
//
// pod-name is the one segment with no payload counterpart. It is required to
// be present and is compared to nothing, because it is diagnostic and never
// authority on its own.
//
// A principal with any other segment count is refused before any value is
// examined.
func validatePodLeaseProfile(p *apb.ZoneAdmissionLeasePayload, principal admissionPrincipal) error {
	for name, value := range map[string]string{
		"subnet_id": p.GetSubnetId(), "owner_scope": p.GetOwnerScope(), "account_id": p.GetAccountId(),
		"namespace_id": p.GetNamespaceId(), "workload_id": p.GetWorkloadId(), "node_id": p.GetNodeId(),
		"pod_id": p.GetPodId(), "pod_instance_id": p.GetPodInstanceId(),
	} {
		if err := requireText(value, name); err != nil {
			return err
		}
	}
	if p.GetAssignmentGeneration() == 0 || p.GetPodInstanceId() != podInstanceID(p.GetPodId(), p.GetAssignmentGeneration()) {
		return fmt.Errorf("%w: pod instance/generation mismatch", ErrAdmissionMalformed)
	}
	if p.GetNodeAdmission() != apb.NodeAdmission_NODE_ADMISSION_UNSPECIFIED || p.GetSessionId() != "" ||
		p.GetSessionKind() != mpb.SessionKind_SESSION_KIND_UNSPECIFIED || p.GetSessionLeg() != mpb.SessionLeg_SESSION_LEG_UNSPECIFIED || p.GetGrantId() != "" ||
		p.GetShareId() != "" {
		return fmt.Errorf("%w: pod lease carries fields from another kind", ErrAdmissionMalformed)
	}
	s := principal.segments
	if len(s) != podPrincipalSegments {
		return fmt.Errorf("%w: pod principal has %d path segments, want %d", ErrAdmissionMalformed, len(s), podPrincipalSegments)
	}
	if s[0] != "subnet" || s[1] != p.GetSubnetId() || s[2] != "account" || s[3] != p.GetAccountId() ||
		s[4] != "namespace" || s[5] != p.GetNamespaceId() || s[6] != "workload" || s[7] != p.GetWorkloadId() ||
		s[8] != "pod-name" || s[9] == "" || s[10] != "pod" || s[11] != p.GetPodId() {
		return fmt.Errorf("%w: pod principal does not match lease", ErrAdmissionMalformed)
	}
	return nil
}

// validateSessionLeaseProfile enforces the session leg. Account and stable
// Namespace ID are required and byte-match their principal segments.
func validateSessionLeaseProfile(p *apb.ZoneAdmissionLeasePayload, principal admissionPrincipal) error {
	for name, value := range map[string]string{
		"subnet_id": p.GetSubnetId(), "owner_scope": p.GetOwnerScope(), "account_id": p.GetAccountId(),
		"namespace_id": p.GetNamespaceId(), "workload_id": p.GetWorkloadId(), "node_id": p.GetNodeId(),
		"pod_id": p.GetPodId(), "pod_instance_id": p.GetPodInstanceId(), "session_id": p.GetSessionId(),
	} {
		if err := requireText(value, name); err != nil {
			return err
		}
	}
	if p.GetAssignmentGeneration() == 0 || p.GetPodInstanceId() != sessionPodInstanceID(p.GetPodId(), p.GetAssignmentGeneration()) {
		return fmt.Errorf("%w: session pod incarnation mismatch", ErrAdmissionMalformed)
	}
	if p.GetNodeAdmission() != apb.NodeAdmission_NODE_ADMISSION_UNSPECIFIED {
		return fmt.Errorf("%w: session lease carries node admission", ErrAdmissionMalformed)
	}
	if p.GetShareId() != "" {
		return fmt.Errorf("%w: session lease carries a share", ErrAdmissionMalformed)
	}
	if p.GetSessionKind() != mpb.SessionKind_SESSION_KIND_EXEC && p.GetSessionKind() != mpb.SessionKind_SESSION_KIND_LOGS && p.GetSessionKind() != mpb.SessionKind_SESSION_KIND_SHELL {
		return fmt.Errorf("%w: unknown session kind %d", ErrAdmissionMalformed, p.GetSessionKind())
	}
	if p.GetSessionLeg() == mpb.SessionLeg_SESSION_LEG_CLIENT {
		if p.GetGrantId() != "" {
			return fmt.Errorf("%w: client session leg carries proxy grant", ErrAdmissionMalformed)
		}
	} else if p.GetSessionLeg() == mpb.SessionLeg_SESSION_LEG_PROXY {
		if err := requireText(p.GetGrantId(), "grant_id"); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("%w: unknown session leg %d", ErrAdmissionMalformed, p.GetSessionLeg())
	}
	s := principal.segments
	kind := strings.ToLower(strings.TrimPrefix(p.GetSessionKind().String(), "SESSION_KIND_"))
	leg := strings.ToLower(strings.TrimPrefix(p.GetSessionLeg().String(), "SESSION_LEG_"))
	pathInstance := p.GetPodId() + "." + strconv.FormatUint(p.GetAssignmentGeneration(), 10)
	if len(s) != sessionPrincipalSegments || s[0] != "subnet" || s[1] != p.GetSubnetId() ||
		s[2] != "account" || s[3] != p.GetAccountId() || s[4] != "namespace" || s[5] != p.GetNamespaceId() ||
		s[6] != "workload" || s[7] != p.GetWorkloadId() || s[8] != "pod" || s[9] != p.GetPodId() ||
		s[10] != "pod-instance" || s[11] != pathInstance || s[12] != "session" || s[13] != kind ||
		s[14] != p.GetSessionId() || s[15] != "leg" || s[16] != leg {
		return fmt.Errorf("%w: session principal does not match lease", ErrAdmissionMalformed)
	}
	return nil
}

// validateShareLeaseProfile enforces the share leg: the data plane,
// an owner scope and a share ID that byte-matches the principal's two-segment
// path, and no field belonging to another endpoint kind.
func validateShareLeaseProfile(p *apb.ZoneAdmissionLeasePayload, principal admissionPrincipal) error {
	if p.GetFabricPlane() != mpb.Plane_PLANE_DATA {
		return fmt.Errorf("%w: share lease names the control plane", ErrAdmissionMalformed)
	}
	if err := requireText(p.GetOwnerScope(), "owner_scope"); err != nil {
		return err
	}
	if err := requireText(p.GetShareId(), "share_id"); err != nil {
		return err
	}
	if p.GetSubnetId() != "" || p.GetAccountId() != "" || p.GetNamespaceId() != "" || p.GetWorkloadId() != "" ||
		p.GetNodeId() != "" || p.GetPodId() != "" || p.GetPodInstanceId() != "" || p.GetAssignmentGeneration() != 0 ||
		p.GetSessionId() != "" || p.GetSessionKind() != mpb.SessionKind_SESSION_KIND_UNSPECIFIED ||
		p.GetSessionLeg() != mpb.SessionLeg_SESSION_LEG_UNSPECIFIED || p.GetGrantId() != "" ||
		p.GetNodeAdmission() != apb.NodeAdmission_NODE_ADMISSION_UNSPECIFIED {
		return fmt.Errorf("%w: share lease carries fields from another kind", ErrAdmissionMalformed)
	}
	s := principal.segments
	if len(s) != sharePrincipalSegments || s[0] != "share" || s[1] != p.GetShareId() {
		return fmt.Errorf("%w: share principal does not match lease", ErrAdmissionMalformed)
	}
	return nil
}

func isCanonicalUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for i := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if (value[i] < '0' || value[i] > '9') && (value[i] < 'a' || value[i] > 'f') {
			return false
		}
	}
	return true
}

func podInstanceID(podID string, generation uint64) string {
	return podID + ":" + strconv.FormatUint(generation, 10)
}

func sessionPodInstanceID(podID string, generation uint64) string {
	return podID + "." + strconv.FormatUint(generation, 10)
}

// BuildDockProofInput returns the canonical raw input that the endpoint's
// SVID key signs. It binds the dock contract, a SHA-256 digest of the lease
// envelope, the requested keepalive, the predecessor generation (if any)
// and the TLS exporter value of this connection, so a proof cannot be
// replayed on another connection or with another lease.
func BuildDockProofInput(leaseEnvelope []byte, keepaliveMs uint32, predecessor *mpb.DockGen, exporter []byte) ([]byte, error) {
	if len(leaseEnvelope) == 0 || len(leaseEnvelope) > apb.MaxLeaseEnvelopeBytes {
		return nil, fmt.Errorf("%w: dock lease envelope size %d", ErrAdmissionMalformed, len(leaseEnvelope))
	}
	if len(exporter) != apb.TLSExporterBytes {
		return nil, fmt.Errorf("%w: dock exporter size %d", ErrAdmissionMalformed, len(exporter))
	}
	if predecessor != nil {
		if err := validateDockGeneration(predecessor); err != nil {
			return nil, err
		}
	}
	digest := sha256.Sum256(leaseEnvelope)
	input := &apb.DockProofInput{
		Version:             apb.DockProofVersion,
		DockContract:        dockpb.Contract,
		ExporterLabel:       apb.TLSExporterLabel,
		ExporterValue:       append([]byte(nil), exporter...),
		LeaseEnvelopeSha256: digest[:],
		KeepaliveMs:         keepaliveMs,
		PredecessorGen:      predecessor,
	}
	raw, err := MarshalCanonical(input)
	if err != nil {
		return nil, fmt.Errorf("%w: dock proof input: %v", ErrAdmissionMalformed, err)
	}
	if len(raw) > apb.MaxDockProofInputBytes {
		return nil, fmt.Errorf("%w: dock proof input size %d", ErrAdmissionMalformed, len(raw))
	}
	return raw, nil
}

// ParseDockProofInput accepts only the unique canonical encoding.
func ParseDockProofInput(raw []byte) (*apb.DockProofInput, error) {
	var input apb.DockProofInput
	if err := unmarshalCanonical(raw, &input, apb.MaxDockProofInputBytes, "dock proof input"); err != nil {
		return nil, err
	}
	if input.GetVersion() != apb.DockProofVersion || input.GetDockContract() != dockpb.Contract || input.GetExporterLabel() != apb.TLSExporterLabel ||
		len(input.GetExporterValue()) != apb.TLSExporterBytes || len(input.GetLeaseEnvelopeSha256()) != apb.SHA256Bytes {
		return nil, fmt.Errorf("%w: dock proof profile", ErrAdmissionMalformed)
	}
	if input.GetPredecessorGen() != nil {
		if err := validateDockGeneration(input.GetPredecessorGen()); err != nil {
			return nil, err
		}
	}
	return &input, nil
}

// DockProofSignatureInput is the exact SVID-key signature input.
func DockProofSignatureInput(rawProofInput []byte) []byte {
	return domainSeparated(apb.DockProofSignatureDomain, rawProofInput)
}

// VerifyDockProof verifies signature and byte-exact agreement with every
// DockHello opening fact plus the exporter from this TLS connection.
func VerifyDockProof(rawProofInput, signature []byte, publicKey ed25519.PublicKey, leaseEnvelope []byte, keepaliveMs uint32, predecessor *mpb.DockGen, exporter []byte) error {
	input, err := ParseDockProofInput(rawProofInput)
	if err != nil {
		return err
	}
	if len(signature) != apb.DockProofSignatureBytes || len(publicKey) != ed25519.PublicKeySize {
		return ErrAdmissionSignature
	}
	digest := sha256.Sum256(leaseEnvelope)
	if input.GetDockContract() != dockpb.Contract || input.GetKeepaliveMs() != keepaliveMs ||
		!proto.Equal(input.GetPredecessorGen(), predecessor) || !bytes.Equal(input.GetExporterValue(), exporter) ||
		!bytes.Equal(input.GetLeaseEnvelopeSha256(), digest[:]) {
		return fmt.Errorf("%w: dock proof does not match opening", ErrAdmissionBinding)
	}
	if !ed25519.Verify(publicKey, DockProofSignatureInput(rawProofInput), signature) {
		return ErrAdmissionSignature
	}
	return nil
}

// ValidateDockHelloV3 refuses missing, unknown, or mismatched opening facts.
// The exporter is compared by VerifyDockProof once TLS supplies its value.
func ValidateDockHelloV3(hello *dockpb.DockHello) error {
	if hello == nil {
		return fmt.Errorf("%w: dock/3 hello absent", ErrAdmissionMalformed)
	}
	if err := rejectUnknown(hello.ProtoReflect()); err != nil {
		return fmt.Errorf("%w: dock/3 unknown content: %v", ErrAdmissionMalformed, err)
	}
	if hello.GetContract() != dockpb.Contract || len(hello.GetLeaseEnvelope()) == 0 || len(hello.GetLeaseEnvelope()) > apb.MaxLeaseEnvelopeBytes ||
		len(hello.GetDockProofInput()) == 0 || len(hello.GetDockProofInput()) > apb.MaxDockProofInputBytes ||
		len(hello.GetDockProofSignature()) != apb.DockProofSignatureBytes {
		return fmt.Errorf("%w: incomplete dock/3 hello", ErrAdmissionMalformed)
	}
	input, err := ParseDockProofInput(hello.GetDockProofInput())
	if err != nil {
		return err
	}
	digest := sha256.Sum256(hello.GetLeaseEnvelope())
	if input.GetDockContract() != hello.GetContract() || input.GetKeepaliveMs() != hello.GetKeepaliveMs() ||
		!proto.Equal(input.GetPredecessorGen(), hello.GetPredecessorGen()) || !bytes.Equal(input.GetLeaseEnvelopeSha256(), digest[:]) {
		return fmt.Errorf("%w: dock proof does not bind complete hello", ErrAdmissionBinding)
	}
	return nil
}

func validateDockGeneration(generation *mpb.DockGen) error {
	if generation == nil || generation.GetEdge() == nil || len(generation.GetEdge().GetIncarnation()) == 0 || len(generation.GetEdge().GetIncarnation()) > apb.MaxIdentifierBytes ||
		len(generation.GetEdge().GetLeaseId()) == 0 || len(generation.GetEdge().GetLeaseId()) > apb.MaxIdentifierBytes ||
		generation.GetSlot() == 0 || len(generation.GetNonce()) != apb.DockGenerationNonceBytes {
		return fmt.Errorf("%w: incomplete exact dock generation", ErrAdmissionMalformed)
	}
	return nil
}

func unmarshalCanonical(raw []byte, message proto.Message, max int, name string) error {
	if len(raw) == 0 || len(raw) > max {
		return fmt.Errorf("%w: %s size %d", ErrAdmissionMalformed, name, len(raw))
	}
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(raw, message); err != nil {
		return fmt.Errorf("%w: %s decode: %v", ErrAdmissionMalformed, name, err)
	}
	canonical, err := MarshalCanonical(message)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrAdmissionMalformed, name, err)
	}
	if !bytes.Equal(raw, canonical) {
		return fmt.Errorf("%w: %s", ErrAdmissionNonCanonical, name)
	}
	return nil
}

func domainSeparated(domain string, raw []byte) []byte {
	out := make([]byte, 0, len(domain)+4+len(raw))
	out = append(out, domain...)
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(raw)))
	out = append(out, size[:]...)
	out = append(out, raw...)
	return out
}

func requireText(value, name string) error {
	if value == "" {
		return fmt.Errorf("%w: %s is required", ErrAdmissionMalformed, name)
	}
	return nil
}

func boundedText(name, value string, max int) error {
	if value == "" || len(value) > max || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("%w: invalid %s", ErrAdmissionMalformed, name)
	}
	return nil
}

func isDNSLabel(value string) bool {
	if value == "" || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}
