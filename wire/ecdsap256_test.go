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

package wire_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"

	"github.com/idyl-labs/hyperplane-go/wire"
	apb "github.com/idyl-labs/hyperplane-go/wire/admissionv3"
)

func p256Order() *big.Int { return elliptic.P256().Params().N }

func p256HalfOrder() *big.Int {
	return new(big.Int).Rsh(p256Order(), 1)
}

// rawSequence assembles arbitrary DER-shaped bytes for hostile encodings.
func rawSequence(chunks ...[]byte) []byte {
	body := bytes.Join(chunks, nil)
	out := []byte{0x30, byte(len(body))}
	return append(out, body...)
}

func rawInteger(content ...byte) []byte {
	out := []byte{0x02, byte(len(content))}
	return append(out, content...)
}

// TestLeaseSignatureSignParseRoundTrip checks that every signature the
// signer produces is strict DER, low-S, and within the size bounds, so a
// verifier that accepts only that one encoding never refuses an honest
// signature.
func TestLeaseSignatureSignParseRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("exact canonical payload bytes")
	for i := 0; i < 64; i++ {
		signature, err := wire.SignZoneAdmissionLease(key, payload)
		if err != nil {
			t.Fatal(err)
		}
		_, s, err := wire.ParseLeaseSignature(signature)
		if err != nil {
			t.Fatalf("produced signature is not canonical: %v", err)
		}
		if s.Cmp(p256HalfOrder()) > 0 {
			t.Fatal("produced signature is high-S")
		}
		if len(signature) < apb.MinLeaseSignatureBytes || len(signature) > apb.MaxLeaseSignatureBytes {
			t.Fatalf("produced signature size %d outside bounds", len(signature))
		}
	}
}

func TestSignZoneAdmissionLeaseRefusesNonP256Signers(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.SignZoneAdmissionLease(p384, []byte("payload")); err == nil {
		t.Fatal("P-384 signer must refuse")
	}
	if _, err := wire.SignZoneAdmissionLease(nil, []byte("payload")); err == nil {
		t.Fatal("absent signer must refuse")
	}
}

// TestParseLeaseSignatureStrictDER checks that the parser accepts exactly
// one encoding per signature. Refusing high-S values and non-minimal or
// malformed DER removes signature malleability: a third party cannot
// produce a second valid byte string for the same signed lease.
func TestParseLeaseSignatureStrictDER(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := wire.SignZoneAdmissionLease(key, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	r, s, err := wire.ParseLeaseSignature(valid)
	if err != nil {
		t.Fatal(err)
	}

	highS := new(big.Int).Sub(p256Order(), s)
	highSSig := rawSequence(rawInteger(paddedIntBytes(r)...), rawInteger(paddedIntBytes(highS)...))
	if _, _, err := wire.ParseLeaseSignature(highSSig); !errors.Is(err, wire.ErrLeaseSignatureEncoding) {
		t.Fatalf("high-S error = %v, want ErrLeaseSignatureEncoding", err)
	}
	normalized, err := wire.NormalizeLeaseSignatureLowS(highSSig)
	if err != nil {
		t.Fatalf("high-S normalization failed: %v", err)
	}
	if _, sNorm, err := wire.ParseLeaseSignature(normalized); err != nil || sNorm.Cmp(p256HalfOrder()) > 0 {
		t.Fatalf("normalized signature invalid: %v", err)
	}

	hostile := map[string][]byte{
		"empty":              {},
		"trailing byte":      append(append([]byte(nil), valid...), 0x00),
		"truncated":          valid[:len(valid)-1],
		"wrong outer tag":    append([]byte{0x31}, valid[1:]...),
		"long-form length":   append([]byte{0x30, 0x81, byte(len(valid) - 2)}, valid[2:]...),
		"wrong integer tag":  rawSequence([]byte{0x03, 0x01, 0x01}, rawInteger(0x01)),
		"non-minimal int":    rawSequence(rawInteger(0x00, 0x01), rawInteger(0x01)),
		"negative int":       rawSequence(rawInteger(0x81), rawInteger(0x01)),
		"zero r":             rawSequence(rawInteger(0x00), rawInteger(0x01)),
		"zero s":             rawSequence(rawInteger(0x01), rawInteger(0x00)),
		"r equals order":     rawSequence(rawInteger(paddedIntBytes(p256Order())...), rawInteger(0x01)),
		"s equals order":     rawSequence(rawInteger(0x01), rawInteger(paddedIntBytes(p256Order())...)),
		"one integer only":   rawSequence(rawInteger(0x01)),
		"three integers":     rawSequence(rawInteger(0x01), rawInteger(0x01), rawInteger(0x01)),
		"sequence too short": {0x30},
	}
	for name, input := range hostile {
		if _, _, err := wire.ParseLeaseSignature(input); !errors.Is(err, wire.ErrLeaseSignatureEncoding) {
			t.Errorf("%s: error = %v, want ErrLeaseSignatureEncoding", name, err)
		}
	}
}

func TestEncodeLeaseSignatureBounds(t *testing.T) {
	if _, err := wire.EncodeLeaseSignature(big.NewInt(0), big.NewInt(1)); err == nil {
		t.Fatal("zero r must refuse")
	}
	if _, err := wire.EncodeLeaseSignature(big.NewInt(1), new(big.Int).Add(p256HalfOrder(), big.NewInt(1))); err == nil {
		t.Fatal("high-S must refuse")
	}
	if _, err := wire.EncodeLeaseSignature(p256Order(), big.NewInt(1)); err == nil {
		t.Fatal("r at order must refuse")
	}
	minimal, err := wire.EncodeLeaseSignature(big.NewInt(1), big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	if len(minimal) != apb.MinLeaseSignatureBytes {
		t.Fatalf("minimal signature is %d bytes, want %d", len(minimal), apb.MinLeaseSignatureBytes)
	}
	if r, s, err := wire.ParseLeaseSignature(minimal); err != nil || r.Cmp(big.NewInt(1)) != 0 || s.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("minimal signature round trip failed: %v", err)
	}
}

// paddedIntBytes emits minimal DER integer content for a positive value,
// adding the sign pad byte when the top bit is set.
func paddedIntBytes(value *big.Int) []byte {
	raw := value.Bytes()
	if len(raw) == 0 {
		return []byte{0x00}
	}
	if raw[0]&0x80 != 0 {
		return append([]byte{0x00}, raw...)
	}
	return raw
}
