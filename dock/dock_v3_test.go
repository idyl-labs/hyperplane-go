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

package dock

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/proto"

	dc "github.com/idyl-labs/hyperplane-go/generation"
	"github.com/idyl-labs/hyperplane-go/wire"
	admissionpb "github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	commonpb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
	dockv3pb "github.com/idyl-labs/hyperplane-go/wire/dockv3"
	"github.com/idyl-labs/hyperplane-go/wire/fallback"
)

func testNodeLease(t *testing.T, now time.Time) []byte {
	t.Helper()
	now = now.UTC().Truncate(time.Second)
	payload := &admissionpb.ZoneAdmissionLeasePayload{
		Version: admissionpb.PayloadVersion, LeaseId: []byte("0123456789abcdef"),
		Zone: "z", FabricPlane: commonpb.Plane_PLANE_DATA,
		Principal:         "spiffe://z.zone.example.test/subnet/s1/node/n1",
		SubjectSpkiSha256: bytes.Repeat([]byte{2}, admissionpb.SHA256Bytes),
		EndpointKind:      commonpb.EndpointKind_ENDPOINT_KIND_NODE,
		SubnetId:          "s1", OwnerScope: "provider:test", NodeId: "n1",
		AdapterClasses: wire.LaneClassStream, LaneClassCeiling: wire.LaneClassStream,
		PolicyProfile: "dynamic-default", PolicyProfileVersion: 1,
		NotBeforeUnixS: uint64(now.Add(-admissionpb.IssuerBackdate).Unix()),
		IssuedAtUnixS:  uint64(now.Unix()), NotAfterUnixS: uint64(now.Add(time.Hour).Unix()),
		NodeAdmission: admissionpb.NodeAdmission_NODE_ADMISSION_PROVIDER,
	}
	payloadRaw, err := wire.MarshalZoneAdmissionLeasePayload(payload)
	if err != nil {
		t.Fatalf("marshal lease payload: %v", err)
	}
	placeholderSignature, err := wire.EncodeLeaseSignature(big.NewInt(3), big.NewInt(3))
	if err != nil {
		t.Fatalf("encode placeholder lease signature: %v", err)
	}
	envelopeRaw, err := wire.MarshalZoneAdmissionLease(&admissionpb.ZoneAdmissionLease{
		Contract: admissionpb.ZoneAdmissionLeaseContract, Payload: payloadRaw,
		Signature:       placeholderSignature,
		SignerKeyId:     bytes.Repeat([]byte{4}, admissionpb.SHA256Bytes),
		SignerCertChain: [][]byte{{5}},
	})
	if err != nil {
		t.Fatalf("marshal lease envelope: %v", err)
	}
	return envelopeRaw
}

func TestDemandAdmissionValidationIsStrictAndSeparateFromDock2(t *testing.T) {
	pki := newTestPKI(t)
	lease := testNodeLease(t, time.Now())
	good := pki.clientConfig()
	good.Admission = &DemandAdmission{
		LeaseEnvelope: lease,
		Signer:        good.SVID.PrivateKey.(ed25519.PrivateKey),
	}
	if _, err := validateDemandAdmission(good); err != nil {
		t.Fatalf("valid dock/3 material refused: %v", err)
	}

	legacy := pki.clientConfig()
	if public, err := validateDemandAdmission(legacy); err != nil || public != nil {
		t.Fatalf("explicit dock/2 selection changed: public=%x err=%v", public, err)
	}

	wrongKey := good
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey.Admission = &DemandAdmission{LeaseEnvelope: lease, Signer: other}
	if _, err := validateDemandAdmission(wrongKey); err == nil {
		t.Fatal("wrong Ed25519 SVID signer accepted")
	}

	nonEd25519 := good
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonEd25519.Admission = &DemandAdmission{LeaseEnvelope: lease, Signer: ecdsaKey}
	if _, err := validateDemandAdmission(nonEd25519); err == nil {
		t.Fatal("non-Ed25519 proof signer accepted")
	}

	missingSigner := good
	missingSigner.Admission = &DemandAdmission{LeaseEnvelope: lease}
	if _, err := validateDemandAdmission(missingSigner); err == nil {
		t.Fatal("missing proof signer accepted")
	}

	nonCanonical := good
	nonCanonicalLease := append(append([]byte(nil), lease...), 0x0a, byte(len(admissionpb.ZoneAdmissionLeaseContract)))
	nonCanonicalLease = append(nonCanonicalLease, admissionpb.ZoneAdmissionLeaseContract...)
	nonCanonical.Admission = &DemandAdmission{LeaseEnvelope: nonCanonicalLease, Signer: good.Admission.Signer}
	if _, err := validateDemandAdmission(nonCanonical); err == nil {
		t.Fatal("non-canonical lease envelope accepted")
	}

	expired := good
	expired.Admission = &DemandAdmission{LeaseEnvelope: testNodeLease(t, time.Now().Add(-2*time.Hour)), Signer: good.Admission.Signer}
	if _, err := validateDemandAdmission(expired); !errors.Is(err, wire.ErrAdmissionExpired) {
		t.Fatalf("expired lease error = %v, want ErrAdmissionExpired", err)
	}
}

type openingStream struct{ bytes.Buffer }

func (*openingStream) Close() error                    { return nil }
func (*openingStream) CancelRead(uint64)               {}
func (*openingStream) CancelWrite(uint64)              {}
func (*openingStream) SetReadDeadline(time.Time) error { return nil }

type openingConn struct {
	exporter []byte
	resumed  bool
	calls    int
	label    string
	context  []byte
}

func (*openingConn) OpenStreamSync(context.Context) (transportStream, error) { panic("unused") }
func (*openingConn) AcceptStream(context.Context) (transportStream, error)   { panic("unused") }
func (*openingConn) AcceptUniStream(context.Context) (transportReceiveStream, error) {
	panic("unused")
}
func (*openingConn) SendKeepalive() error                { return nil }
func (*openingConn) CloseWithError(uint64, string) error { return nil }
func (*openingConn) Context() context.Context            { return context.Background() }
func (c *openingConn) Resumed() bool                     { return c.resumed }
func (c *openingConn) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	c.calls++
	c.label = label
	c.context = make([]byte, len(context))
	copy(c.context, context)
	if length != len(c.exporter) {
		return nil, errors.New("unexpected exporter length")
	}
	return append([]byte(nil), c.exporter...), nil
}

func framedBody(t *testing.T, framed []byte) []byte {
	t.Helper()
	if len(framed) < 4 {
		t.Fatal("opening frame is truncated")
	}
	n := int(binary.BigEndian.Uint32(framed[:4]))
	if n != len(framed)-4 {
		t.Fatalf("opening frame length = %d, body = %d", n, len(framed)-4)
	}
	return framed[4:]
}

func TestDock3OpeningUsesFreshExporterAndCanonicalExactProof(t *testing.T) {
	pki := newTestPKI(t)
	lease := testNodeLease(t, time.Now())
	privateKey := pki.clientCert.PrivateKey.(ed25519.PrivateKey)
	cfg := pki.clientConfig()
	cfg.KeepaliveMs = 20_000
	cfg.Predecessor = &dc.DockGen{
		Edge: dc.EdgeTag{Incarnation: "edge-incarnation", LeaseID: "route-lease"},
		Slot: 7, Epoch: 9, Nonce: "noncenonce12",
	}
	cfg.Admission = &DemandAdmission{LeaseEnvelope: lease, Signer: privateKey}
	public, err := validateDemandAdmission(cfg)
	if err != nil {
		t.Fatal(err)
	}
	predecessor, err := wire.GenToProtoV2(*cfg.Predecessor)
	if err != nil {
		t.Fatal(err)
	}

	assertOpening := func(exporter []byte, resumed bool) (*dockv3pb.DockHello, []byte) {
		t.Helper()
		stream := &openingStream{}
		conn := &openingConn{exporter: exporter, resumed: resumed}
		if err := writeDockOpening(stream, conn, cfg, predecessor, public); err != nil {
			t.Fatalf("write dock/3 opening: %v", err)
		}
		if conn.calls != 1 || conn.label != admissionpb.TLSExporterLabel || conn.context == nil || len(conn.context) != 0 {
			t.Fatalf("exporter call = count %d label %q context %#v", conn.calls, conn.label, conn.context)
		}
		body := framedBody(t, stream.Bytes())
		var opening dockv3pb.ClientToEdge
		if err := proto.Unmarshal(body, &opening); err != nil {
			t.Fatalf("decode dock/3 opening: %v", err)
		}
		canonical, err := wire.MarshalCanonical(&opening)
		if err != nil || !bytes.Equal(canonical, body) {
			t.Fatal("dock/3 opening frame is not exact canonical protobuf")
		}
		hello := opening.GetHello()
		if hello == nil || hello.GetContract() != dockv3pb.Contract || !bytes.Equal(hello.GetLeaseEnvelope(), lease) {
			t.Fatal("dock/3 opening did not preserve contract and exact lease")
		}
		if err := wire.VerifyDockProof(hello.GetDockProofInput(), hello.GetDockProofSignature(), public, lease, cfg.KeepaliveMs, predecessor, exporter); err != nil {
			t.Fatalf("recompute exact dock proof: %v", err)
		}
		return hello, append([]byte(nil), body...)
	}

	firstExporter := bytes.Repeat([]byte{0x44}, admissionpb.TLSExporterBytes)
	first, firstBody := assertOpening(firstExporter, false)
	secondExporter := bytes.Repeat([]byte{0x55}, admissionpb.TLSExporterBytes)
	second, secondBody := assertOpening(secondExporter, true)
	if bytes.Equal(first.GetDockProofInput(), second.GetDockProofInput()) || bytes.Equal(firstBody, secondBody) {
		t.Fatal("resumed dock reused the predecessor connection's exporter proof")
	}
	if err := wire.VerifyDockProof(first.GetDockProofInput(), first.GetDockProofSignature(), public, lease, cfg.KeepaliveMs, predecessor, secondExporter); err == nil {
		t.Fatal("dock proof replayed across TLS connections")
	}
}

func TestDock2OpeningRemainsASeparateCleanContract(t *testing.T) {
	cfg := Config{KeepaliveMs: 20_000}
	stream := &openingStream{}
	conn := &openingConn{exporter: bytes.Repeat([]byte{1}, admissionpb.TLSExporterBytes)}
	if err := writeDockOpening(stream, conn, cfg, nil, nil); err != nil {
		t.Fatal(err)
	}
	if conn.calls != 0 {
		t.Fatal("dock/2 opening unexpectedly derived a dock/3 exporter")
	}
	var opening dockv3pb.ClientToEdge
	if err := proto.Unmarshal(framedBody(t, stream.Bytes()), &opening); err != nil {
		t.Fatal(err)
	}
	hello := opening.GetHello()
	if hello == nil || hello.GetContract() != "dock/2" || len(hello.GetLeaseEnvelope()) != 0 || len(hello.GetDockProofInput()) != 0 || len(hello.GetDockProofSignature()) != 0 {
		t.Fatalf("dock/2 opening contaminated by dock/3 material: %+v", hello)
	}
}

type observedDock3 struct {
	hello    *dockv3pb.DockHello
	exporter []byte
	resumed  bool
	err      error
}

func observeDock3Opening(stream io.ReadWriter, exporter []byte, resumed bool, public ed25519.PublicKey, lease []byte) observedDock3 {
	body, err := wire.ReadRawFrame(stream, 0)
	if err != nil {
		return observedDock3{err: err}
	}
	var opening dockv3pb.ClientToEdge
	if err := proto.Unmarshal(body, &opening); err != nil {
		return observedDock3{err: err}
	}
	canonical, err := wire.MarshalCanonical(&opening)
	if err != nil || !bytes.Equal(canonical, body) {
		return observedDock3{err: errors.New("opening is not canonical")}
	}
	hello := opening.GetHello()
	if hello == nil || !bytes.Equal(hello.GetLeaseEnvelope(), lease) {
		return observedDock3{err: errors.New("opening omitted the exact lease")}
	}
	if err := wire.ValidateDockHelloV3(hello); err != nil {
		return observedDock3{err: err}
	}
	if err := wire.VerifyDockProof(hello.GetDockProofInput(), hello.GetDockProofSignature(), public,
		lease, hello.GetKeepaliveMs(), hello.GetPredecessorGen(), exporter); err != nil {
		return observedDock3{err: err}
	}
	return observedDock3{hello: hello, exporter: exporter, resumed: resumed}
}

func welcomeFor(attempt int) *dockv3pb.EdgeToClient {
	return &dockv3pb.EdgeToClient{Msg: &dockv3pb.EdgeToClient_Welcome{Welcome: &dockv3pb.DockWelcome{
		Gen: &commonpb.DockGen{
			Edge: &commonpb.EdgeTag{Incarnation: []byte("edge-incarnation"), LeaseId: []byte("route-lease")},
			Slot: uint32(attempt + 1), SlotEpoch: 1, Nonce: []byte(fmt.Sprintf("%012d", attempt+1)),
		},
		KeepaliveMs: 20_000,
	}}}
}

func dock3IntegrationConfig(t *testing.T, pki *testPKI, endpoint string, lease []byte) Config {
	t.Helper()
	cfg := pki.clientConfig()
	cfg.Endpoint = endpoint
	cfg.KeepaliveMs = 20_000
	cfg.DisableKeepalive = true
	cfg.SessionCache = tls.NewLRUClientSessionCache(8)
	cfg.Admission = &DemandAdmission{
		LeaseEnvelope: lease,
		Signer:        cfg.SVID.PrivateKey.(ed25519.PrivateKey),
	}
	return cfg
}

// Both transport implementations must export from the connection that
// carries the opening. The second attempt resumes TLS and still proves with a
// different exporter; a cached proof would fail the server-side recomputation.
func TestOpenDock3ProofMatchesQUICAndFallbackExportersOnFullAndResumedTLS(t *testing.T) {
	for _, transport := range []string{"quic", "fallback"} {
		t.Run(transport, func(t *testing.T) {
			pki := newTestPKI(t)
			lease := testNodeLease(t, time.Now())
			public := pki.clientCert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
			observed := make(chan observedDock3, 4)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			serverTLS := &tls.Config{
				Certificates: []tls.Certificate{pki.serverCert}, MinVersion: tls.VersionTLS13,
				ClientAuth: tls.RequireAnyClientCert,
			}
			var endpoint string
			var stop func()
			switch transport {
			case "quic":
				serverTLS.NextProtos = []string{"idyl/2"}
				listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{})
				if err != nil {
					t.Fatal(err)
				}
				endpoint = listener.Addr().String()
				stop = func() { _ = listener.Close() }
				go func() {
					for attempt := 0; attempt < 2; attempt++ {
						conn, err := listener.Accept(ctx)
						if err != nil {
							observed <- observedDock3{err: err}
							return
						}
						state := conn.ConnectionState().TLS
						exporter, err := state.ExportKeyingMaterial(admissionpb.TLSExporterLabel, []byte{}, admissionpb.TLSExporterBytes)
						if err != nil {
							observed <- observedDock3{err: err}
							return
						}
						stream, err := conn.AcceptStream(ctx)
						if err != nil {
							observed <- observedDock3{err: err}
							return
						}
						got := observeDock3Opening(stream, exporter, state.DidResume, public, lease)
						if got.err == nil {
							got.err = wire.WriteFrame(stream, welcomeFor(attempt))
						}
						observed <- got
					}
				}()
			case "fallback":
				serverTLS.NextProtos = []string{fallback.ALPN}
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				endpoint = listener.Addr().String()
				stop = func() { _ = listener.Close() }
				go func() {
					for attempt := 0; attempt < 2; attempt++ {
						raw, err := listener.Accept()
						if err != nil {
							observed <- observedDock3{err: err}
							return
						}
						tlsConn := tls.Server(raw, serverTLS)
						if err := tlsConn.HandshakeContext(ctx); err != nil {
							observed <- observedDock3{err: err}
							return
						}
						state := tlsConn.ConnectionState()
						exporter, err := state.ExportKeyingMaterial(admissionpb.TLSExporterLabel, []byte{}, admissionpb.TLSExporterBytes)
						if err != nil {
							observed <- observedDock3{err: err}
							return
						}
						mux := fallback.Server(tlsConn, 0)
						stream, err := mux.AcceptStream(ctx)
						if err != nil {
							observed <- observedDock3{err: err}
							return
						}
						got := observeDock3Opening(stream, exporter, state.DidResume, public, lease)
						if got.err == nil {
							got.err = wire.WriteFrame(stream, welcomeFor(attempt))
						}
						observed <- got
					}
				}()
			}
			defer stop()

			cfg := dock3IntegrationConfig(t, pki, endpoint, lease)
			if transport == "fallback" {
				cfg.ForceFallback = true
			}
			var attempts []observedDock3
			for attempt := 0; attempt < 2; attempt++ {
				dock, err := Open(ctx, cfg)
				if err != nil {
					t.Fatalf("Open attempt %d: %v", attempt, err)
				}
				got := <-observed
				if got.err != nil {
					t.Fatalf("server verify attempt %d: %v", attempt, got.err)
				}
				if got.resumed != dock.Resumed() {
					t.Fatalf("attempt %d resumption differs: server=%v client=%v", attempt, got.resumed, dock.Resumed())
				}
				attempts = append(attempts, got)
				gen := dock.Gen()
				cfg.Predecessor = &gen
				// Let TLS 1.3 session tickets reach the client cache before the
				// incumbent connection is retired.
				time.Sleep(150 * time.Millisecond)
				_ = dock.Close()
			}
			if attempts[0].resumed {
				t.Fatal("first dock unexpectedly resumed")
			}
			if !attempts[1].resumed {
				t.Fatal("second dock did not exercise TLS resumption")
			}
			if bytes.Equal(attempts[0].exporter, attempts[1].exporter) || bytes.Equal(attempts[0].hello.GetDockProofInput(), attempts[1].hello.GetDockProofInput()) {
				t.Fatal("resumed dock reused exporter or proof")
			}
		})
	}
}

var _ io.Writer = (*openingStream)(nil)
