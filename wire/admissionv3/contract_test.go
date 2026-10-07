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

package admissionv3_test

import (
	"strings"
	"testing"
	"time"

	"github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	"github.com/idyl-labs/hyperplane-go/wire/dockv3"
)

// TestContractStrings pins the contract identifiers, signature domains,
// and signer paths. Every one of them is carried on the wire or folded
// into a signature input, so changing any byte breaks every peer.
func TestContractStrings(t *testing.T) {
	for _, row := range []struct {
		name, got, want string
	}{
		{"ZoneAdmissionLeaseContract", admissionv3.ZoneAdmissionLeaseContract, "zone-admission-lease/3"},
		{"ZoneAdmissionLeaseSignatureDomain", admissionv3.ZoneAdmissionLeaseSignatureDomain, "idyl-zone-admission-lease-signature/v3\x00"},
		{"DockProofSignatureDomain", admissionv3.DockProofSignatureDomain, "idyl-dock-proof-signature/v1\x00"},
		{"DockContract", admissionv3.DockContract, "dock/3"},
		{"TLSExporterLabel", admissionv3.TLSExporterLabel, "EXPORTER-IDYL-DOCK-PROOF-v1"},
		{"ControlPlaneAdmissionSignerPath", admissionv3.ControlPlaneAdmissionSignerPath, "/service/join/admission-issuer"},
		{"DataPlaneAdmissionSignerPath", admissionv3.DataPlaneAdmissionSignerPath, "/service/controller/admission-issuer"},
	} {
		if row.got != row.want {
			t.Errorf("%s = %q, want %q", row.name, row.got, row.want)
		}
	}
}

// TestDockContractAgreesWithDockPackage checks that the dock protocol a
// dock proof binds to is the protocol dockv3 speaks. If the two diverged,
// every honest dock proof would name a protocol its hello does not.
func TestDockContractAgreesWithDockPackage(t *testing.T) {
	if admissionv3.DockContract != dockv3.Contract {
		t.Fatalf("admissionv3.DockContract %q != dockv3.Contract %q", admissionv3.DockContract, dockv3.Contract)
	}
}

// TestSignatureDomainsAreSeparated checks that the two signature domains
// are NUL-terminated and neither is a prefix of the other, so a signature
// made for one purpose can never verify as the other.
func TestSignatureDomainsAreSeparated(t *testing.T) {
	lease, proof := admissionv3.ZoneAdmissionLeaseSignatureDomain, admissionv3.DockProofSignatureDomain
	for _, domain := range []string{lease, proof} {
		if !strings.HasSuffix(domain, "\x00") || strings.Count(domain, "\x00") != 1 {
			t.Errorf("domain %q is not a single NUL-terminated string", domain)
		}
	}
	if strings.HasPrefix(lease, proof) || strings.HasPrefix(proof, lease) {
		t.Fatal("one signature domain is a prefix of the other")
	}
	if !strings.Contains(lease, "/v3") {
		t.Fatalf("lease domain %q does not name the contract version", lease)
	}
}

// TestSignerPathsAreDistinctPerPlane checks that each fabric plane has its
// own signer identity, so a signer for one plane can never admit an
// endpoint to the other.
func TestSignerPathsAreDistinctPerPlane(t *testing.T) {
	control, data := admissionv3.ControlPlaneAdmissionSignerPath, admissionv3.DataPlaneAdmissionSignerPath
	if control == data || strings.HasPrefix(control, data) || strings.HasPrefix(data, control) {
		t.Fatalf("signer paths overlap: %q, %q", control, data)
	}
	for _, path := range []string{control, data} {
		if !strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") || strings.Contains(path, "//") {
			t.Errorf("signer path %q is not a canonical absolute path", path)
		}
	}
}

// TestNumericBounds pins every size, version, and duration bound. Peers in
// other languages enforce the same numbers, so they are part of the
// contract.
func TestNumericBounds(t *testing.T) {
	for _, row := range []struct {
		name      string
		got, want int
	}{
		{"PayloadVersion", admissionv3.PayloadVersion, 3},
		{"DockProofVersion", admissionv3.DockProofVersion, 1},
		{"MaxLeaseEnvelopeBytes", admissionv3.MaxLeaseEnvelopeBytes, 16 * 1024},
		{"MaxLeasePayloadBytes", admissionv3.MaxLeasePayloadBytes, 4 * 1024},
		{"MaxSignerCertificateDER", admissionv3.MaxSignerCertificateDER, 4 * 1024},
		{"MaxSignerChainLength", admissionv3.MaxSignerChainLength, 4},
		{"MaxSignerChainDERBytes", admissionv3.MaxSignerChainDERBytes, 12 * 1024},
		{"MaxDockProofInputBytes", admissionv3.MaxDockProofInputBytes, 1024},
		{"LeaseIDBytes", admissionv3.LeaseIDBytes, 16},
		{"SHA256Bytes", admissionv3.SHA256Bytes, 32},
		{"TLSExporterBytes", admissionv3.TLSExporterBytes, 32},
		{"DockGenerationNonceBytes", admissionv3.DockGenerationNonceBytes, 12},
		{"MinLeaseSignatureBytes", admissionv3.MinLeaseSignatureBytes, 8},
		{"MaxLeaseSignatureBytes", admissionv3.MaxLeaseSignatureBytes, 72},
		{"DockProofSignatureBytes", admissionv3.DockProofSignatureBytes, 64},
		{"MaxZoneBytes", admissionv3.MaxZoneBytes, 63},
		{"MaxPrincipalBytes", admissionv3.MaxPrincipalBytes, 1024},
		{"MaxIdentifierBytes", admissionv3.MaxIdentifierBytes, 255},
		{"MaxPolicyProfileBytes", admissionv3.MaxPolicyProfileBytes, 64},
	} {
		if row.got != row.want {
			t.Errorf("%s = %d, want %d", row.name, row.got, row.want)
		}
	}
	if got, want := uint64(admissionv3.MaxMicropodSequence), uint64(9_007_199_254_740_991); got != want {
		t.Errorf("MaxMicropodSequence = %d, want %d", got, want)
	}
	for _, row := range []struct {
		name      string
		got, want time.Duration
	}{
		{"IssuerBackdate", admissionv3.IssuerBackdate, time.Minute},
		{"VerifierClockGrace", admissionv3.VerifierClockGrace, 0},
		{"MaxAdmissionSignerLifetime", admissionv3.MaxAdmissionSignerLifetime, 24 * time.Hour},
		{"MaxNodeLeaseLifetime", admissionv3.MaxNodeLeaseLifetime, 24 * time.Hour},
		{"MaxSessionLeaseLifetime", admissionv3.MaxSessionLeaseLifetime, time.Hour},
		{"MaxShareLeaseLifetime", admissionv3.MaxShareLeaseLifetime, time.Hour},
	} {
		if row.got != row.want {
			t.Errorf("%s = %v, want %v", row.name, row.got, row.want)
		}
	}
}

// TestBoundsAreMutuallyConsistent checks the relations between bounds
// that the contract depends on: a maximal payload and a maximal signer
// chain each fit in one envelope, the aggregate chain bound is reachable and binding, an
// ECDSA P-256 DER signature always fits the signature bounds, a node lease
// cannot outlive the signer that admits it, and a dock proof input can
// carry its fixed-size fields.
func TestBoundsAreMutuallyConsistent(t *testing.T) {
	if admissionv3.MaxLeasePayloadBytes >= admissionv3.MaxLeaseEnvelopeBytes || admissionv3.MaxSignerChainDERBytes >= admissionv3.MaxLeaseEnvelopeBytes {
		t.Error("a maximal payload or signer chain alone does not fit one envelope")
	}
	if admissionv3.MaxSignerChainDERBytes < admissionv3.MaxSignerCertificateDER ||
		admissionv3.MaxSignerChainDERBytes >= admissionv3.MaxSignerChainLength*admissionv3.MaxSignerCertificateDER {
		t.Error("aggregate chain bound is either unreachable or not binding")
	}
	// A DER ECDSA P-256 signature is SEQUENCE { INTEGER r, INTEGER s }: each
	// integer at most 33 content bytes plus a two-byte header, and a
	// two-byte sequence header; the smallest has one-byte integers.
	if maxDER := 2 + 2*(2+33); admissionv3.MaxLeaseSignatureBytes != maxDER {
		t.Errorf("MaxLeaseSignatureBytes %d, largest P-256 DER signature %d", admissionv3.MaxLeaseSignatureBytes, maxDER)
	}
	if minDER := 2 + 2*(2+1); admissionv3.MinLeaseSignatureBytes != minDER {
		t.Errorf("MinLeaseSignatureBytes %d, smallest DER signature %d", admissionv3.MinLeaseSignatureBytes, minDER)
	}
	if admissionv3.MaxNodeLeaseLifetime > admissionv3.MaxAdmissionSignerLifetime ||
		admissionv3.MaxSessionLeaseLifetime > admissionv3.MaxAdmissionSignerLifetime ||
		admissionv3.MaxShareLeaseLifetime > admissionv3.MaxAdmissionSignerLifetime {
		t.Error("a lease kind may outlive the longest admission signer")
	}
	if admissionv3.IssuerBackdate <= 0 || admissionv3.VerifierClockGrace != 0 {
		t.Error("issuer backdate must be positive and verifier grace zero")
	}
	fixed := admissionv3.TLSExporterBytes + admissionv3.SHA256Bytes + admissionv3.DockGenerationNonceBytes +
		len(admissionv3.TLSExporterLabel) + len(admissionv3.DockContract)
	if fixed >= admissionv3.MaxDockProofInputBytes {
		t.Errorf("a dock proof input's fixed fields take %d of %d bytes", fixed, admissionv3.MaxDockProofInputBytes)
	}
}
