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

// Package conformance defines the zone-admission-lease/3 conformance
// corpus: the vector schema, the bounded vocabulary of refusal classes,
// and the reference evaluation. The corpus generator uses it to record
// each vector's verdict, and this module's tests use it to derive the
// verdicts again. Any implementation, in any language, must produce the
// same verdict for every vector, and each of its refusals must map to the
// vector's refusal class.
package conformance

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/idyl-labs/hyperplane-go/wire"
)

// Refusal classes. Every refused vector names exactly one, and no other
// value is valid.
const (
	ClassUnsupportedContract = "unsupported_contract"
	ClassMalformed           = "malformed"
	ClassNonCanonical        = "non_canonical"
	ClassNotYetValid         = "not_yet_valid"
	ClassExpired             = "expired"
	ClassSignerProfile       = "signer_profile"
	ClassSignerValidity      = "signer_validity"
	ClassUntrustedSigner     = "untrusted_signer"
	ClassRevokedSigner       = "revoked_signer"
	ClassLeaseOutsideSigner  = "lease_outside_signer"
	ClassSignature           = "signature"
)

// Corpus is the JSON shape of the committed corpus file.
type Corpus struct {
	Contract    string   `json:"contract"`
	GeneratedBy string   `json:"generated_by"`
	Notes       []string `json:"notes,omitempty"`
	Vectors     []Vector `json:"vectors"`
}

// Vector is one complete verification input with its reference verdict:
// the lease envelope, the expected signer URI, the trust bundle, the
// revoked signer key IDs, and the verification time. Verdict is "valid"
// or "refused"; RefusalClass is set only when the verdict is "refused".
type Vector struct {
	Name                   string   `json:"name"`
	Description            string   `json:"description"`
	EnvelopeHex            string   `json:"envelope_hex"`
	ExpectedSignerURI      string   `json:"expected_signer_uri"`
	TrustBundleDERHex      []string `json:"trust_bundle_der_hex"`
	RevokedSignerKeyIDsHex []string `json:"revoked_signer_key_ids_hex"`
	NowUnixS               uint64   `json:"now_unix_s"`
	Verdict                string   `json:"verdict"`
	RefusalClass           string   `json:"refusal_class,omitempty"`
}

// Evaluate runs the reference evaluation of v: a canonical parse of the
// envelope with the payload's validity interval checked at the vector's
// time, then full signer verification against the vector's trust bundle,
// expected signer URI, and revocations. It returns the verdict "valid"
// with an empty class, or "refused" with exactly one refusal class. A
// non-nil error means the vector itself could not be decoded.
func Evaluate(v Vector) (string, string, error) {
	envelopeRaw, err := hex.DecodeString(v.EnvelopeHex)
	if err != nil {
		return "", "", fmt.Errorf("vector %s: envelope hex: %w", v.Name, err)
	}
	bundle := make([]*x509.Certificate, 0, len(v.TrustBundleDERHex))
	for i, anchorHex := range v.TrustBundleDERHex {
		anchorDER, err := hex.DecodeString(anchorHex)
		if err != nil {
			return "", "", fmt.Errorf("vector %s: bundle %d hex: %w", v.Name, i, err)
		}
		anchor, err := x509.ParseCertificate(anchorDER)
		if err != nil {
			return "", "", fmt.Errorf("vector %s: bundle %d: %w", v.Name, i, err)
		}
		bundle = append(bundle, anchor)
	}
	revoked := make([][]byte, 0, len(v.RevokedSignerKeyIDsHex))
	for i, keyIDHex := range v.RevokedSignerKeyIDsHex {
		keyID, err := hex.DecodeString(keyIDHex)
		if err != nil {
			return "", "", fmt.Errorf("vector %s: revoked %d hex: %w", v.Name, i, err)
		}
		revoked = append(revoked, keyID)
	}

	envelope, _, err := wire.ParseZoneAdmissionLease(envelopeRaw, v.NowUnixS)
	if err != nil {
		return "refused", Classify(err), nil
	}
	if _, err := wire.VerifyZoneAdmissionLeaseSigner(envelope, bundle, v.ExpectedSignerURI, revoked, time.Unix(int64(v.NowUnixS), 0).UTC()); err != nil {
		return "refused", Classify(err), nil
	}
	return "valid", "", nil
}

// Classify maps a refusal error to its refusal class. The cases are
// checked in order, so the most specific class wins when an error wraps
// several causes. An error with no typed cause classifies as malformed.
func Classify(err error) string {
	switch {
	case errors.Is(err, wire.ErrAdmissionUnsupportedContract):
		return ClassUnsupportedContract
	case errors.Is(err, wire.ErrAdmissionNonCanonical):
		return ClassNonCanonical
	case errors.Is(err, wire.ErrAdmissionNotYetValid):
		return ClassNotYetValid
	case errors.Is(err, wire.ErrAdmissionExpired):
		return ClassExpired
	case errors.Is(err, wire.ErrAdmissionLeaseOutsideSigner):
		return ClassLeaseOutsideSigner
	case errors.Is(err, wire.ErrAdmissionSignerRevoked):
		return ClassRevokedSigner
	case errors.Is(err, wire.ErrAdmissionSignerUntrusted):
		return ClassUntrustedSigner
	case errors.Is(err, wire.ErrAdmissionSignerValidity):
		return ClassSignerValidity
	case errors.Is(err, wire.ErrAdmissionSignerProfile):
		return ClassSignerProfile
	case errors.Is(err, wire.ErrAdmissionSignature), errors.Is(err, wire.ErrLeaseSignatureEncoding):
		return ClassSignature
	default:
		return ClassMalformed
	}
}
