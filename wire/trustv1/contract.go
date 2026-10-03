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

// Package trustv1 defines trust snapshots: bounded, sequenced sets of
// public CA certificates for one zone and one purpose, with the validators
// and the successor rule a consumer applies before installing one.
//
// A snapshot carries public certificates only; private key material has no
// field in this contract. A snapshot's digest is SHA-256 over its exact
// canonical JSON payload, never over a protobuf encoding, and the
// structured fields must agree with that payload byte for byte.
package trustv1

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
)

// Size and validity bounds every snapshot must satisfy.
const (
	SHA256Bytes = 32
	// MaxGenerations bounds the CA generations in one snapshot. It leaves
	// room for overlapping rotation: the active generations, earlier
	// generations retained while leaves they issued remain valid, and
	// generations introduced for accelerated recovery.
	MaxGenerations               = 16
	MaxCertificateDERBytes       = 16 * 1024
	MaxCanonicalPayloadJSONBytes = 384 * 1024
	MaxZoneBytes                 = 63
	MaxGenerationIDBytes         = 128

	MaxSnapshotValidity = 24 * time.Hour
)

// Errors returned by the validators and by JudgeSuccessor.
var (
	// ErrMalformed marks a snapshot that fails structural, canonical-form,
	// certificate, or digest validation.
	ErrMalformed = errors.New("trustv1: malformed snapshot")
	// ErrExpired marks a snapshot evaluated outside [issued_at, valid_until).
	ErrExpired = errors.New("trustv1: expired snapshot")
	// ErrRollback marks a successor whose sequence is lower than the
	// installed snapshot's.
	ErrRollback = errors.New("trustv1: sequence rollback")
	// ErrEquivocation marks a successor with the installed snapshot's
	// sequence but a different digest.
	ErrEquivocation = errors.New("trustv1: sequence equivocation")
	// ErrWrongZone marks a successor for a different zone.
	ErrWrongZone = errors.New("trustv1: wrong zone")
	// ErrWrongPurpose marks a successor for a different purpose.
	ErrWrongPurpose = errors.New("trustv1: wrong purpose")

	zonePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
)

type canonicalSnapshotPayload struct {
	Zone        string                `json:"zone"`
	Purpose     string                `json:"purpose"`
	Sequence    uint64                `json:"sequence"`
	IssuedAt    time.Time             `json:"issuedAt"`
	ValidUntil  time.Time             `json:"validUntil"`
	Generations []canonicalGeneration `json:"generations"`
}

type canonicalGeneration struct {
	GenerationID      string    `json:"generationId"`
	CertificateDER    []byte    `json:"certificateDer"`
	SHA256Fingerprint string    `json:"sha256Fingerprint"`
	NotBefore         time.Time `json:"notBefore"`
	NotAfter          time.Time `json:"notAfter"`
	PublishedSequence uint64    `json:"publishedSequence"`
	State             string    `json:"state"`
}

// NewTrustSnapshot sorts copies of the supplied generations by generation
// ID, builds the exact canonical JSON payload, records its raw SHA-256
// digest, and returns the snapshot only if it passes ValidateTrustSnapshot.
func NewTrustSnapshot(zone string, purpose Purpose, sequence uint64, issuedAt, validUntil time.Time, generations []*TrustGeneration) (*TrustSnapshot, error) {
	generations = cloneGenerations(generations)
	sort.Slice(generations, func(i, j int) bool {
		return generations[i].GetGenerationId() < generations[j].GetGenerationId()
	})
	snapshot := &TrustSnapshot{
		Zone:            zone,
		Purpose:         purpose,
		Sequence:        sequence,
		IssuedAtUnixS:   issuedAt.UTC().Unix(),
		ValidUntilUnixS: validUntil.UTC().Unix(),
		Generations:     generations,
	}
	payload, err := CanonicalTrustSnapshotPayload(snapshot)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	snapshot.CanonicalPayloadJson = payload
	snapshot.Sha256Digest = digest[:]
	if err := ValidateTrustSnapshot(snapshot); err != nil {
		return nil, err
	}
	return snapshot, nil
}

// CanonicalTrustSnapshotPayload returns the canonical JSON payload for the
// snapshot's structured fields. It does not validate the snapshot; callers
// that need a validated snapshot also call ValidateTrustSnapshot or
// ValidateTrustSnapshotAt.
func CanonicalTrustSnapshotPayload(snapshot *TrustSnapshot) ([]byte, error) {
	if snapshot == nil {
		return nil, fmt.Errorf("%w: absent", ErrMalformed)
	}
	purpose, ok := purposeText(snapshot.GetPurpose())
	if !ok {
		return nil, fmt.Errorf("%w: purpose %d", ErrMalformed, snapshot.GetPurpose())
	}
	payload := canonicalSnapshotPayload{
		Zone:        snapshot.GetZone(),
		Purpose:     purpose,
		Sequence:    snapshot.GetSequence(),
		IssuedAt:    time.Unix(snapshot.GetIssuedAtUnixS(), 0).UTC(),
		ValidUntil:  time.Unix(snapshot.GetValidUntilUnixS(), 0).UTC(),
		Generations: make([]canonicalGeneration, 0, len(snapshot.GetGenerations())),
	}
	for _, generation := range snapshot.GetGenerations() {
		if generation == nil {
			return nil, fmt.Errorf("%w: nil generation", ErrMalformed)
		}
		state, ok := stateText(generation.GetState())
		if !ok {
			return nil, fmt.Errorf("%w: generation state %d", ErrMalformed, generation.GetState())
		}
		payload.Generations = append(payload.Generations, canonicalGeneration{
			GenerationID:      generation.GetGenerationId(),
			CertificateDER:    append([]byte(nil), generation.GetCertificateDer()...),
			SHA256Fingerprint: hex.EncodeToString(generation.GetSha256Fingerprint()),
			NotBefore:         time.Unix(generation.GetNotBeforeUnixS(), 0).UTC(),
			NotAfter:          time.Unix(generation.GetNotAfterUnixS(), 0).UTC(),
			PublishedSequence: generation.GetPublishedSequence(),
			State:             state,
		})
	}
	return json.Marshal(payload)
}

// ParseCanonicalTrustSnapshotPayload strictly parses a canonical JSON
// payload and reconstructs the structured snapshot. digest is the raw
// SHA-256 digest of payload. Unknown fields, trailing data, and any
// payload that does not re-encode to exactly the same bytes are refused,
// and the result must pass ValidateTrustSnapshot.
func ParseCanonicalTrustSnapshotPayload(payload, digest []byte) (*TrustSnapshot, error) {
	if len(payload) == 0 || len(payload) > MaxCanonicalPayloadJSONBytes || len(digest) != SHA256Bytes {
		return nil, fmt.Errorf("%w: payload or digest size", ErrMalformed)
	}
	var decoded canonicalSnapshotPayload
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return nil, fmt.Errorf("%w: canonical JSON: %v", ErrMalformed, err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	purpose, ok := parsePurposeText(decoded.Purpose)
	if !ok {
		return nil, fmt.Errorf("%w: purpose %q", ErrMalformed, decoded.Purpose)
	}
	generations := make([]*TrustGeneration, 0, len(decoded.Generations))
	for _, generation := range decoded.Generations {
		state, ok := parseStateText(generation.State)
		if !ok {
			return nil, fmt.Errorf("%w: generation state %q", ErrMalformed, generation.State)
		}
		fingerprint, err := hex.DecodeString(generation.SHA256Fingerprint)
		if err != nil {
			return nil, fmt.Errorf("%w: fingerprint: %v", ErrMalformed, err)
		}
		generations = append(generations, &TrustGeneration{
			GenerationId:      generation.GenerationID,
			CertificateDer:    append([]byte(nil), generation.CertificateDER...),
			Sha256Fingerprint: fingerprint,
			NotBeforeUnixS:    generation.NotBefore.UTC().Unix(),
			NotAfterUnixS:     generation.NotAfter.UTC().Unix(),
			PublishedSequence: generation.PublishedSequence,
			State:             state,
		})
	}
	snapshot := &TrustSnapshot{
		Zone:                 decoded.Zone,
		Purpose:              purpose,
		Sequence:             decoded.Sequence,
		IssuedAtUnixS:        decoded.IssuedAt.UTC().Unix(),
		ValidUntilUnixS:      decoded.ValidUntil.UTC().Unix(),
		Generations:          generations,
		CanonicalPayloadJson: append([]byte(nil), payload...),
		Sha256Digest:         append([]byte(nil), digest...),
	}
	canonical, err := CanonicalTrustSnapshotPayload(snapshot)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, payload) {
		return nil, fmt.Errorf("%w: JSON is not canonical", ErrMalformed)
	}
	if err := ValidateTrustSnapshot(snapshot); err != nil {
		return nil, err
	}
	return snapshot, nil
}

// ValidateTrustSnapshot checks a snapshot without reference to the clock:
// known zone, purpose and positive sequence; a validity interval of at
// most MaxSnapshotValidity; between one and MaxGenerations generations,
// sorted and unique by ID and by certificate; every generation an Ed25519
// signing CA whose advertised validity and fingerprint match its
// certificate, which outlives the snapshot, published no later than the
// snapshot's sequence, and in a distributable state (PUBLISHING, ACTIVE or
// RETIRING); and a canonical payload and digest that match the structured
// fields. Unknown protobuf fields are refused.
func ValidateTrustSnapshot(snapshot *TrustSnapshot) error {
	if snapshot == nil || hasUnknown(snapshot) {
		return fmt.Errorf("%w: absent or unknown fields", ErrMalformed)
	}
	if !validZone(snapshot.GetZone()) || snapshot.GetSequence() == 0 {
		return fmt.Errorf("%w: zone or sequence", ErrMalformed)
	}
	if _, ok := purposeText(snapshot.GetPurpose()); !ok {
		return fmt.Errorf("%w: purpose", ErrMalformed)
	}
	issuedAt := time.Unix(snapshot.GetIssuedAtUnixS(), 0).UTC()
	validUntil := time.Unix(snapshot.GetValidUntilUnixS(), 0).UTC()
	if snapshot.GetIssuedAtUnixS() <= 0 || !validUntil.After(issuedAt) || validUntil.Sub(issuedAt) > MaxSnapshotValidity {
		return fmt.Errorf("%w: snapshot validity", ErrMalformed)
	}
	if len(snapshot.GetGenerations()) == 0 || len(snapshot.GetGenerations()) > MaxGenerations {
		return fmt.Errorf("%w: generation count %d", ErrMalformed, len(snapshot.GetGenerations()))
	}
	seenIDs := make(map[string]struct{}, len(snapshot.GetGenerations()))
	seenFingerprints := make(map[[SHA256Bytes]byte]struct{}, len(snapshot.GetGenerations()))
	previousID := ""
	for index, generation := range snapshot.GetGenerations() {
		if generation == nil || hasUnknown(generation) {
			return fmt.Errorf("%w: generation %d absent or unknown fields", ErrMalformed, index)
		}
		id := generation.GetGenerationId()
		if !validText(id, MaxGenerationIDBytes) || (index > 0 && id <= previousID) {
			return fmt.Errorf("%w: generation IDs are invalid, duplicate, or unsorted", ErrMalformed)
		}
		previousID = id
		if _, exists := seenIDs[id]; exists {
			return fmt.Errorf("%w: duplicate generation ID", ErrMalformed)
		}
		seenIDs[id] = struct{}{}
		certificateDER := generation.GetCertificateDer()
		if len(certificateDER) == 0 || len(certificateDER) > MaxCertificateDERBytes {
			return fmt.Errorf("%w: generation %q certificate size", ErrMalformed, id)
		}
		certificate, err := x509.ParseCertificate(certificateDER)
		if err != nil {
			return fmt.Errorf("%w: generation %q certificate: %v", ErrMalformed, id, err)
		}
		if _, ok := certificate.PublicKey.(ed25519.PublicKey); !ok || !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return fmt.Errorf("%w: generation %q is not an Ed25519 signing CA", ErrMalformed, id)
		}
		if generation.GetNotBeforeUnixS() != certificate.NotBefore.UTC().Unix() || generation.GetNotAfterUnixS() != certificate.NotAfter.UTC().Unix() || !certificate.NotAfter.After(certificate.NotBefore) {
			return fmt.Errorf("%w: generation %q advertised validity differs from certificate", ErrMalformed, id)
		}
		if validUntil.After(certificate.NotAfter.UTC()) {
			return fmt.Errorf("%w: snapshot outlives generation %q", ErrMalformed, id)
		}
		fingerprint := sha256.Sum256(certificateDER)
		if !bytes.Equal(generation.GetSha256Fingerprint(), fingerprint[:]) {
			return fmt.Errorf("%w: generation %q fingerprint", ErrMalformed, id)
		}
		if _, exists := seenFingerprints[fingerprint]; exists {
			return fmt.Errorf("%w: duplicate generation certificate", ErrMalformed)
		}
		seenFingerprints[fingerprint] = struct{}{}
		if generation.GetPublishedSequence() == 0 || generation.GetPublishedSequence() > snapshot.GetSequence() {
			return fmt.Errorf("%w: generation %q published sequence", ErrMalformed, id)
		}
		switch generation.GetState() {
		case GenerationState_GENERATION_STATE_PUBLISHING,
			GenerationState_GENERATION_STATE_ACTIVE,
			GenerationState_GENERATION_STATE_RETIRING:
		default:
			return fmt.Errorf("%w: generation %q is not distributable in state %s", ErrMalformed, id, generation.GetState())
		}
	}
	payload := snapshot.GetCanonicalPayloadJson()
	if len(payload) == 0 || len(payload) > MaxCanonicalPayloadJSONBytes || len(snapshot.GetSha256Digest()) != SHA256Bytes {
		return fmt.Errorf("%w: canonical payload or digest size", ErrMalformed)
	}
	canonical, err := CanonicalTrustSnapshotPayload(snapshot)
	if err != nil {
		return err
	}
	if !bytes.Equal(payload, canonical) {
		return fmt.Errorf("%w: canonical payload mismatch", ErrMalformed)
	}
	digest := sha256.Sum256(payload)
	if !bytes.Equal(snapshot.GetSha256Digest(), digest[:]) {
		return fmt.Errorf("%w: snapshot digest mismatch", ErrMalformed)
	}
	return nil
}

// ValidateTrustSnapshotAt applies ValidateTrustSnapshot and then requires
// now to fall within [issued_at, valid_until), returning ErrExpired
// otherwise.
func ValidateTrustSnapshotAt(snapshot *TrustSnapshot, now time.Time) error {
	if err := ValidateTrustSnapshot(snapshot); err != nil {
		return err
	}
	now = now.UTC()
	if now.Before(time.Unix(snapshot.GetIssuedAtUnixS(), 0).UTC()) || !now.Before(time.Unix(snapshot.GetValidUntilUnixS(), 0).UTC()) {
		return ErrExpired
	}
	return nil
}

// JudgeSuccessor decides whether next may replace current, the installed
// snapshot; current may be nil. Installs are monotonic: next must be valid
// and have the same zone and purpose, a lower sequence is a rollback, and
// the same sequence with a different digest is equivocation. duplicate is
// true only for a re-delivery of the current snapshot's exact sequence and
// digest, which a consumer can treat as already applied.
func JudgeSuccessor(current, next *TrustSnapshot) (duplicate bool, err error) {
	if err := ValidateTrustSnapshot(next); err != nil {
		return false, err
	}
	if current == nil {
		return false, nil
	}
	if err := ValidateTrustSnapshot(current); err != nil {
		return false, fmt.Errorf("%w: current snapshot invalid: %v", ErrMalformed, err)
	}
	if next.GetZone() != current.GetZone() {
		return false, ErrWrongZone
	}
	if next.GetPurpose() != current.GetPurpose() {
		return false, ErrWrongPurpose
	}
	switch {
	case next.GetSequence() < current.GetSequence():
		return false, ErrRollback
	case next.GetSequence() == current.GetSequence() && !bytes.Equal(next.GetSha256Digest(), current.GetSha256Digest()):
		return false, ErrEquivocation
	case next.GetSequence() == current.GetSequence():
		return true, nil
	default:
		return false, nil
	}
}

func purposeText(purpose Purpose) (string, bool) {
	switch purpose {
	case Purpose_PURPOSE_JOIN:
		return "JOIN", true
	case Purpose_PURPOSE_POD:
		return "POD", true
	default:
		return "", false
	}
}

func parsePurposeText(value string) (Purpose, bool) {
	switch value {
	case "JOIN":
		return Purpose_PURPOSE_JOIN, true
	case "POD":
		return Purpose_PURPOSE_POD, true
	default:
		return Purpose_PURPOSE_UNSPECIFIED, false
	}
}

func stateText(state GenerationState) (string, bool) {
	switch state {
	case GenerationState_GENERATION_STATE_PUBLISHING:
		return "PUBLISHING", true
	case GenerationState_GENERATION_STATE_ACTIVE:
		return "ACTIVE", true
	case GenerationState_GENERATION_STATE_RETIRING:
		return "RETIRING", true
	case GenerationState_GENERATION_STATE_RETIRED:
		return "RETIRED", true
	case GenerationState_GENERATION_STATE_REVOKED:
		return "REVOKED", true
	default:
		return "", false
	}
}

func parseStateText(value string) (GenerationState, bool) {
	switch value {
	case "PUBLISHING":
		return GenerationState_GENERATION_STATE_PUBLISHING, true
	case "ACTIVE":
		return GenerationState_GENERATION_STATE_ACTIVE, true
	case "RETIRING":
		return GenerationState_GENERATION_STATE_RETIRING, true
	case "RETIRED":
		return GenerationState_GENERATION_STATE_RETIRED, true
	case "REVOKED":
		return GenerationState_GENERATION_STATE_REVOKED, true
	default:
		return GenerationState_GENERATION_STATE_UNSPECIFIED, false
	}
}

func cloneGenerations(input []*TrustGeneration) []*TrustGeneration {
	output := make([]*TrustGeneration, 0, len(input))
	for _, generation := range input {
		if generation == nil {
			output = append(output, nil)
			continue
		}
		output = append(output, proto.Clone(generation).(*TrustGeneration))
	}
	return output
}

func validZone(value string) bool {
	return len(value) > 0 && len(value) <= MaxZoneBytes && zonePattern.MatchString(value)
}

func validText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x21 || r == 0x7f {
			return false
		}
	}
	return true
}

func hasUnknown(message proto.Message) bool {
	return len(message.ProtoReflect().GetUnknown()) != 0
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("%w: trailing JSON value", ErrMalformed)
		}
		return fmt.Errorf("%w: trailing JSON: %v", ErrMalformed, err)
	}
	return nil
}
