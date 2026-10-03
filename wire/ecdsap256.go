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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	apb "github.com/idyl-labs/hyperplane-go/wire/admissionv3"
)

// ecdsap256.go: the admission lease signature encoding. Lease signatures
// are ECDSA P-256 over SHA-256 in strict ASN.1 DER with a canonical low-S
// value, so exactly one signature encoding exists for any signed payload.
// Producers normalize; verifiers refuse every non-canonical encoding
// instead of repairing it. Dock proofs use a separate scheme: fixed-width
// Ed25519 signatures under the endpoint's own SVID key.

var (
	p256Order     = elliptic.P256().Params().N
	p256HalfOrder = new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)
)

// ErrLeaseSignatureEncoding names a lease signature whose bytes are not the
// canonical strict-DER low-S encoding, independent of whether the underlying
// signature would verify.
var ErrLeaseSignatureEncoding = errors.New("wire: lease signature is not canonical strict-DER low-S ECDSA P-256")

// ParseLeaseSignature strictly parses one canonical ECDSA P-256 lease
// signature. It rejects trailing bytes, non-minimal lengths, non-minimal or
// non-positive integers, out-of-range scalars, and high-S values.
func ParseLeaseSignature(der []byte) (r, s *big.Int, err error) {
	if len(der) < apb.MinLeaseSignatureBytes || len(der) > apb.MaxLeaseSignatureBytes {
		return nil, nil, fmt.Errorf("%w: size %d", ErrLeaseSignatureEncoding, len(der))
	}
	if der[0] != 0x30 {
		return nil, nil, fmt.Errorf("%w: not a DER sequence", ErrLeaseSignatureEncoding)
	}
	// Maximum content length is 70 bytes, so only short-form lengths are
	// canonical anywhere inside a lease signature.
	if int(der[1]) != len(der)-2 || der[1] >= 0x80 {
		return nil, nil, fmt.Errorf("%w: sequence length", ErrLeaseSignatureEncoding)
	}
	body := der[2:]
	r, rest, err := parseStrictDERInteger(body)
	if err != nil {
		return nil, nil, err
	}
	s, rest, err = parseStrictDERInteger(rest)
	if err != nil {
		return nil, nil, err
	}
	if len(rest) != 0 {
		return nil, nil, fmt.Errorf("%w: trailing bytes", ErrLeaseSignatureEncoding)
	}
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(p256Order) >= 0 || s.Cmp(p256Order) >= 0 {
		return nil, nil, fmt.Errorf("%w: scalar out of range", ErrLeaseSignatureEncoding)
	}
	if s.Cmp(p256HalfOrder) > 0 {
		return nil, nil, fmt.Errorf("%w: high-S", ErrLeaseSignatureEncoding)
	}
	return r, s, nil
}

func parseStrictDERInteger(body []byte) (*big.Int, []byte, error) {
	if len(body) < 3 || body[0] != 0x02 {
		return nil, nil, fmt.Errorf("%w: integer tag", ErrLeaseSignatureEncoding)
	}
	length := int(body[1])
	if body[1] >= 0x80 || length == 0 || len(body) < 2+length {
		return nil, nil, fmt.Errorf("%w: integer length", ErrLeaseSignatureEncoding)
	}
	content := body[2 : 2+length]
	if content[0]&0x80 != 0 {
		return nil, nil, fmt.Errorf("%w: negative integer", ErrLeaseSignatureEncoding)
	}
	if length > 1 && content[0] == 0x00 && content[1]&0x80 == 0 {
		return nil, nil, fmt.Errorf("%w: non-minimal integer", ErrLeaseSignatureEncoding)
	}
	return new(big.Int).SetBytes(content), body[2+length:], nil
}

// EncodeLeaseSignature produces the unique canonical encoding for in-range
// low-S scalars. It refuses scalars a strict parser would reject.
func EncodeLeaseSignature(r, s *big.Int) ([]byte, error) {
	if r == nil || s == nil || r.Sign() <= 0 || s.Sign() <= 0 ||
		r.Cmp(p256Order) >= 0 || s.Cmp(p256Order) >= 0 || s.Cmp(p256HalfOrder) > 0 {
		return nil, fmt.Errorf("%w: scalar out of range", ErrLeaseSignatureEncoding)
	}
	rBytes := minimalDERInteger(r)
	sBytes := minimalDERInteger(s)
	body := make([]byte, 0, 4+len(rBytes)+len(sBytes))
	body = append(body, 0x02, byte(len(rBytes)))
	body = append(body, rBytes...)
	body = append(body, 0x02, byte(len(sBytes)))
	body = append(body, sBytes...)
	out := make([]byte, 0, 2+len(body))
	out = append(out, 0x30, byte(len(body)))
	out = append(out, body...)
	return out, nil
}

func minimalDERInteger(value *big.Int) []byte {
	raw := value.Bytes()
	if len(raw) == 0 {
		return []byte{0x00}
	}
	if raw[0]&0x80 != 0 {
		return append([]byte{0x00}, raw...)
	}
	return raw
}

// NormalizeLeaseSignatureLowS accepts a freshly produced ECDSA DER signature
// (for example crypto.Signer output), flips a high-S value to its canonical
// low-S twin, and returns the unique strict encoding.
func NormalizeLeaseSignatureLowS(der []byte) ([]byte, error) {
	r, s, err := parseProducedSignature(der)
	if err != nil {
		return nil, err
	}
	if s.Cmp(p256HalfOrder) > 0 {
		s = new(big.Int).Sub(p256Order, s)
	}
	return EncodeLeaseSignature(r, s)
}

// parseProducedSignature parses locally produced DER without the low-S rule:
// the producer normalizes immediately after signing, so high-S is expected
// here and only here.
func parseProducedSignature(der []byte) (*big.Int, *big.Int, error) {
	if len(der) < apb.MinLeaseSignatureBytes || len(der) > apb.MaxLeaseSignatureBytes || der[0] != 0x30 ||
		int(der[1]) != len(der)-2 || der[1] >= 0x80 {
		return nil, nil, fmt.Errorf("%w: produced signature framing", ErrLeaseSignatureEncoding)
	}
	r, rest, err := parseStrictDERInteger(der[2:])
	if err != nil {
		return nil, nil, err
	}
	s, rest, err := parseStrictDERInteger(rest)
	if err != nil {
		return nil, nil, err
	}
	if len(rest) != 0 {
		return nil, nil, fmt.Errorf("%w: trailing bytes", ErrLeaseSignatureEncoding)
	}
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(p256Order) >= 0 || s.Cmp(p256Order) >= 0 {
		return nil, nil, fmt.Errorf("%w: scalar out of range", ErrLeaseSignatureEncoding)
	}
	return r, s, nil
}

// SignZoneAdmissionLease signs canonical payload bytes under the zone
// admission lease signature domain with an ECDSA P-256 signer and returns
// the canonical low-S DER signature. The signer is expected to be a live
// X.509-SVID private key; a signer whose public key is not ECDSA P-256 is
// refused.
func SignZoneAdmissionLease(signer crypto.Signer, payloadBytes []byte) ([]byte, error) {
	if signer == nil {
		return nil, fmt.Errorf("%w: signer absent", ErrAdmissionSignature)
	}
	publicKey, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: lease signer key is not ECDSA P-256", ErrAdmissionSignature)
	}
	digest := sha256.Sum256(ZoneAdmissionLeaseSignatureInput(payloadBytes))
	produced, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAdmissionSignature, err)
	}
	return NormalizeLeaseSignatureLowS(produced)
}

// verifyLeaseSignatureP256 verifies a canonical lease signature over the
// exact transmitted payload bytes.
func verifyLeaseSignatureP256(publicKey *ecdsa.PublicKey, payloadBytes, signature []byte) error {
	if publicKey == nil || publicKey.Curve != elliptic.P256() {
		return fmt.Errorf("%w: lease signer key is not ECDSA P-256", ErrAdmissionSignature)
	}
	r, s, err := ParseLeaseSignature(signature)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(ZoneAdmissionLeaseSignatureInput(payloadBytes))
	if !ecdsa.Verify(publicKey, digest[:], r, s) {
		return ErrAdmissionSignature
	}
	return nil
}
