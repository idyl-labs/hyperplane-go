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
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	dc "github.com/idyl-labs/hyperplane-go/generation"
	"github.com/idyl-labs/hyperplane-go/wire"
	admissionpb "github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	commonpb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
	dockpb "github.com/idyl-labs/hyperplane-go/wire/dockv2"
	"github.com/idyl-labs/hyperplane-go/wire/fallback"
)

// dock_open_paths_test.go: every way opening a dock can fail before it
// returns a dock, and the keepalive scheduler. Local failures (invalid
// configuration or admission material) must be reported before any
// network activity; failures after a connection exists must release that
// connection; and no failure may echo the predecessor's nonce.

// ErrOverloaded renders the edge's retry hint and survives wrapping, so a
// caller can recover the hint with errors.As.
func TestErrOverloadedRendersRetryHintAndUnwraps(t *testing.T) {
	err := fmt.Errorf("open: %w", ErrOverloaded{RetryAfter: 1500 * time.Millisecond})
	var over ErrOverloaded
	if !errors.As(err, &over) || over.RetryAfter != 1500*time.Millisecond {
		t.Fatalf("errors.As = %v, %+v", errors.As(err, &over), over)
	}
	if got := over.Error(); !strings.Contains(got, "1.5s") || !strings.HasPrefix(got, "dock: ") {
		t.Fatalf("Error() = %q, want the dock prefix and the 1.5s hint", got)
	}
	if got := (ErrOverloaded{}).Error(); !strings.Contains(got, "0s") {
		t.Fatalf("zero hint renders %q, want 0s", got)
	}
}

// countingListener is a TCP listener that counts the connections it
// accepts, so a test can prove that no dial happened.
func countingListener(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var n atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			_ = c.Close()
		}
	}()
	return ln.Addr().String(), &n
}

// Invalid dock/3 material is a local judgment: Open refuses it before it
// dials, so a client never spends an edge connection on an opening that
// could not succeed.
func TestOpenRefusesInvalidDemandAdmissionBeforeDialing(t *testing.T) {
	pki := newTestPKI(t)
	lease := testNodeLease(t, time.Now())
	signer := pki.clientCert.PrivateKey.(ed25519.PrivateKey)
	endpoint, accepted := countingListener(t)

	cases := map[string]struct {
		mutate func(*Config)
		is     error
	}{
		"empty lease":        {func(c *Config) { c.Admission.LeaseEnvelope = nil }, wire.ErrAdmissionMalformed},
		"truncated lease":    {func(c *Config) { c.Admission.LeaseEnvelope = lease[:len(lease)/2] }, nil},
		"nil signer":         {func(c *Config) { c.Admission.Signer = nil }, nil},
		"no SVID leaf":       {func(c *Config) { c.SVID = tls.Certificate{} }, nil},
		"unparseable leaf":   {func(c *Config) { c.SVID = tls.Certificate{Certificate: [][]byte{{0x30, 0x00}}, PrivateKey: signer} }, nil},
		"expired lease":      {func(c *Config) { c.Admission.LeaseEnvelope = testNodeLease(t, time.Now().Add(-2*time.Hour)) }, wire.ErrAdmissionExpired},
		"signer not ed25519": {func(c *Config) { c.Admission.Signer = rsaLikeSigner{} }, nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := pki.clientConfig()
			cfg.Endpoint, cfg.ForceFallback = endpoint, true
			cfg.Admission = &DemandAdmission{LeaseEnvelope: lease, Signer: signer}
			tc.mutate(&cfg)
			d, err := Open(laneCtx(t), cfg)
			if err == nil || d != nil {
				t.Fatalf("Open = %v, %v; want a local refusal", d, err)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("Open = %v, want %v", err, tc.is)
			}
		})
	}
	if n := accepted.Load(); n != 0 {
		t.Fatalf("Open dialed the edge %d times for invalid admission material", n)
	}
}

// rsaLikeSigner is a crypto.Signer whose public key is not Ed25519.
type rsaLikeSigner struct{}

func (rsaLikeSigner) Public() crypto.PublicKey { return []byte("not-an-ed25519-key") }
func (rsaLikeSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("unused")
}

// clientTLS refuses configurations that cannot authenticate both ends,
// and a valid one pins TLS 1.3, the client's SVID, the offered ALPN and
// the session cache.
func TestClientTLSRefusesIncompleteIdentity(t *testing.T) {
	pki := newTestPKI(t)
	cases := map[string]struct {
		mutate func(*Config)
		alpn   []string
		want   string
	}{
		"no ALPN":     {func(*Config) {}, nil, "no ALPN"},
		"no ServerID": {func(c *Config) { c.ServerID = spiffeid.ID{} }, quicALPNOffer, "ServerID is required"},
		"no Bundles":  {func(c *Config) { c.Bundles = nil }, quicALPNOffer, "Bundles is required"},
		"no SVID":     {func(c *Config) { c.SVID.Certificate = nil }, quicALPNOffer, "SVID certificate and key"},
		"no SVID key": {func(c *Config) { c.SVID.PrivateKey = nil }, quicALPNOffer, "SVID certificate and key"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := pki.clientConfig()
			tc.mutate(&cfg)
			conf, err := clientTLS(cfg, tc.alpn...)
			if err == nil || conf != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("clientTLS = %v, %v; want an error naming %q", conf, err, tc.want)
			}
		})
	}

	cfg := pki.clientConfig()
	cfg.SessionCache = tls.NewLRUClientSessionCache(1)
	conf, err := clientTLS(cfg, "proto-a")
	if err != nil {
		t.Fatalf("clientTLS on a complete config: %v", err)
	}
	if conf.MinVersion != tls.VersionTLS13 || len(conf.Certificates) != 1 || conf.ClientSessionCache != cfg.SessionCache ||
		len(conf.NextProtos) != 1 || conf.NextProtos[0] != "proto-a" {
		t.Fatalf("clientTLS = min %#x certs %d cache %v alpn %v", conf.MinVersion, len(conf.Certificates), conf.ClientSessionCache, conf.NextProtos)
	}
}

// An incomplete identity fails Open on the QUIC leg and on the fallback
// leg, so the joined error names the missing field.
func TestOpenReportsMissingIdentityOnBothLegs(t *testing.T) {
	pki := newTestPKI(t)
	ln := fallbackListener(t, pki)
	cfg := pki.clientConfig()
	cfg.ServerID = spiffeid.ID{}
	cfg.Endpoint = deadQUICEndpoint(t)
	cfg.FallbackEndpoint = ln.Addr().String()
	d, err := Open(laneCtx(t), cfg)
	if err == nil || d != nil {
		t.Fatalf("Open = %v, %v; want a refusal", d, err)
	}
	if !strings.Contains(err.Error(), "ServerID is required") {
		t.Fatalf("Open = %v, want the missing ServerID named", err)
	}
}

// A fallback dial that cannot build its TLS configuration closes the TCP
// connection it already opened: the edge sees EOF, not a leaked socket.
func TestDialFallbackClosesSocketWhenTLSConfigInvalid(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	peerEOF := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			peerEOF <- err
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = c.Read(make([]byte, 1))
		peerEOF <- err
	}()
	cfg := Config{Endpoint: ln.Addr().String()} // no identity at all
	if conn, err := dialFallback(laneCtx(t), cfg, time.Second); err == nil {
		_ = conn.CloseWithError(0, "unexpected")
		t.Fatal("dialFallback succeeded without an identity")
	}
	if err := <-peerEOF; !errors.Is(err, io.EOF) {
		t.Fatalf("edge read after the refused dial = %v, want EOF", err)
	}
}

// The fallback authenticates the edge by its exact SPIFFE ID: a handshake
// with an edge presenting a different ID from the same trust domain
// fails, and the failure is reported as a handshake error.
func TestDialFallbackRefusesEdgeWithAnotherSPIFFEID(t *testing.T) {
	pki := newTestPKI(t)
	ln := fallbackListener(t, pki)
	cfg := pki.clientConfig()
	cfg.Endpoint = ln.Addr().String()
	cfg.ServerID = spiffeid.RequireFromPath(pki.td, "/fabric/other-edge")
	conn, err := dialFallback(laneCtx(t), cfg, time.Second)
	if err == nil {
		_ = conn.CloseWithError(0, "unexpected")
		t.Fatal("dialFallback accepted an edge with another SPIFFE ID")
	}
	if !strings.Contains(err.Error(), "fallback handshake") {
		t.Fatalf("dialFallback = %v, want a handshake error", err)
	}
}

// LocalIP binds the source address on both transports; a value that is
// not an IP address is refused before any socket is opened.
func TestLocalIPBindsSourceAddressOnBothTransports(t *testing.T) {
	pki := newTestPKI(t)

	t.Run("quic", func(t *testing.T) {
		qln, err := quicListen(pki)
		if err != nil {
			t.Fatalf("quic listen: %v", err)
		}
		defer func() { _ = qln.Close() }()
		cfg := pki.clientConfig()
		cfg.Endpoint = qln.Addr().String()
		cfg.LocalIP = "127.0.0.1"
		conn, err := dialQUIC(laneCtx(t), cfg, 15*time.Second)
		if err != nil {
			t.Fatalf("dialQUIC with LocalIP: %v", err)
		}
		edge, err := qln.Accept(laneCtx(t))
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		if ip := edge.RemoteAddr().(*net.UDPAddr).IP; !ip.Equal(net.ParseIP("127.0.0.1")) {
			t.Fatalf("edge saw source %s, want 127.0.0.1", ip)
		}
		_ = conn.CloseWithError(0, "done")
		_ = edge.CloseWithError(0, "done")
	})

	t.Run("fallback", func(t *testing.T) {
		ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
			Certificates: []tls.Certificate{pki.serverCert}, NextProtos: []string{fallback.ALPN}, MinVersion: tls.VersionTLS13,
		})
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer func() { _ = ln.Close() }()
		source := make(chan net.Addr, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			source <- c.RemoteAddr()
			_ = c.(*tls.Conn).Handshake()
		}()
		cfg := pki.clientConfig()
		cfg.Endpoint = ln.Addr().String()
		cfg.LocalIP = "127.0.0.1"
		conn, err := dialFallback(laneCtx(t), cfg, 15*time.Second)
		if err != nil {
			t.Fatalf("dialFallback with LocalIP: %v", err)
		}
		defer func() { _ = conn.CloseWithError(0, "done") }()
		if ip := (<-source).(*net.TCPAddr).IP; !ip.Equal(net.ParseIP("127.0.0.1")) {
			t.Fatalf("edge saw source %s, want 127.0.0.1", ip)
		}
	})

	for _, transport := range []string{"quic", "fallback"} {
		t.Run(transport+" refuses a non-IP", func(t *testing.T) {
			cfg := pki.clientConfig()
			cfg.Endpoint = "127.0.0.1:9"
			cfg.LocalIP = "edge.example.com"
			var err error
			if transport == "quic" {
				_, err = dialQUIC(laneCtx(t), cfg, time.Second)
			} else {
				_, err = dialFallback(laneCtx(t), cfg, time.Second)
			}
			if err == nil || !strings.Contains(err.Error(), `LocalIP "edge.example.com" is not an IP address`) {
				t.Fatalf("dial = %v, want the LocalIP refusal", err)
			}
		})
	}
}

// A source-bound QUIC dial reports an endpoint it cannot resolve, a source
// address it cannot bind, and a dial that never completes, each as an
// error and without a connection.
func TestSourceBoundQUICDialFailures(t *testing.T) {
	pki := newTestPKI(t)
	cfg := pki.clientConfig()
	cfg.LocalIP = "127.0.0.1"

	cfg.Endpoint = "missing-port.example.com"
	if conn, err := dialQUIC(laneCtx(t), cfg, time.Second); err == nil || conn != nil {
		t.Fatalf("dialQUIC to an endpoint without a port = %v, %v", conn, err)
	}

	cfg.Endpoint = deadQUICEndpoint(t)
	bad := cfg
	bad.LocalIP = "192.0.2.1" // a documentation address no host owns
	if conn, err := dialQUIC(laneCtx(t), bad, time.Second); err == nil || conn != nil {
		t.Fatalf("dialQUIC bound to an address this host does not own = %v, %v", conn, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	conn, err := dialQUIC(ctx, cfg, time.Second)
	if err == nil || conn != nil {
		t.Fatalf("dialQUIC to a silent endpoint = %v, %v", conn, err)
	}
	if !strings.HasPrefix(err.Error(), "dock: dial: ") {
		t.Fatalf("dialQUIC = %v, want the dial error wrapped", err)
	}
}

// When both transports fail to connect, the error carries both causes, so
// an operator can see why each leg failed.
func TestDialTransportJoinsBothLegErrors(t *testing.T) {
	pki := newTestPKI(t)
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	fallbackAddr := closed.Addr().String()
	_ = closed.Close()

	cfg := pki.clientConfig()
	cfg.Endpoint = deadQUICEndpoint(t)
	cfg.FallbackEndpoint = fallbackAddr
	cfg.FallbackThreshold = 100 * time.Millisecond
	conn, transport, err := dialTransport(laneCtx(t), cfg, time.Second)
	if err == nil || conn != nil || transport != "" {
		t.Fatalf("dialTransport = %v, %q, %v; want both legs to fail", conn, transport, err)
	}
	if msg := err.Error(); !strings.Contains(msg, "dock: dial: ") || !strings.Contains(msg, "dock: fallback dial: ") {
		t.Fatalf("dialTransport = %q, want both the QUIC and the fallback cause", msg)
	}
}

// scriptConn is a transportConn whose opening behaviour is scripted: the
// control stream it opens, or the error it opens with, and a record of
// how the connection was closed.
type scriptConn struct {
	ctx     context.Context
	cancel  context.CancelFunc
	openErr error
	control transportStream

	mu     sync.Mutex
	closes []uint64
}

func newScriptConn(control transportStream, openErr error) *scriptConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &scriptConn{ctx: ctx, cancel: cancel, control: control, openErr: openErr}
}

func (c *scriptConn) OpenStreamSync(context.Context) (transportStream, error) {
	if c.openErr != nil {
		return nil, c.openErr
	}
	return c.control, nil
}
func (c *scriptConn) AcceptStream(ctx context.Context) (transportStream, error) {
	<-c.ctx.Done()
	return nil, c.ctx.Err()
}
func (c *scriptConn) AcceptUniStream(ctx context.Context) (transportReceiveStream, error) {
	<-c.ctx.Done()
	return nil, c.ctx.Err()
}
func (c *scriptConn) SendKeepalive() error { return nil }
func (c *scriptConn) CloseWithError(code uint64, _ string) error {
	c.mu.Lock()
	c.closes = append(c.closes, code)
	c.mu.Unlock()
	c.cancel()
	return nil
}
func (c *scriptConn) Context() context.Context { return c.ctx }
func (c *scriptConn) Resumed() bool            { return false }
func (c *scriptConn) ExportKeyingMaterial(_ string, _ []byte, length int) ([]byte, error) {
	return testExporter(length), nil
}

// abandonedWith reports the codes the connection was closed with.
func (c *scriptConn) abandonedWith() []uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]uint64(nil), c.closes...)
}

// replyStream is a control stream that records the hello and serves a
// scripted edge reply; afterReply runs once the reply has been read in
// full.
type replyStream struct {
	hello      bytes.Buffer
	reply      *bytes.Reader
	afterReply func()
	writeErr   error
}

func (s *replyStream) Read(p []byte) (int, error) {
	if s.reply.Len() == 0 {
		return 0, io.EOF
	}
	n, err := s.reply.Read(p)
	if s.reply.Len() == 0 && s.afterReply != nil {
		s.afterReply()
		s.afterReply = nil
	}
	return n, err
}
func (s *replyStream) Write(p []byte) (int, error) {
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	return s.hello.Write(p)
}
func (*replyStream) Close() error                    { return nil }
func (*replyStream) CancelRead(uint64)               {}
func (*replyStream) CancelWrite(uint64)              {}
func (*replyStream) SetReadDeadline(time.Time) error { return nil }

func welcomeBytes(t *testing.T, keepaliveMs uint32) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := wire.WriteFrame(&b, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_Welcome{Welcome: &dockpb.DockWelcome{
		Gen: &commonpb.DockGen{
			Edge: &commonpb.EdgeTag{Incarnation: []byte("edge-a"), LeaseId: []byte("lease-a")},
			Slot: 3, SlotEpoch: 1, Nonce: []byte("nonce-000003"),
		},
		KeepaliveMs: keepaliveMs,
	}}}); err != nil {
		t.Fatalf("welcome frame: %v", err)
	}
	return b.Bytes()
}

// A control stream that cannot be opened fails the opening with the
// transport's own error, and the connection is abandoned with
// DockCodeProtocol rather than left open.
func TestOpenDockAbandonsConnectionWhenControlStreamFails(t *testing.T) {
	errOpen := errors.New("control open refused")
	conn := newScriptConn(nil, errOpen)
	d, err := openDock(context.Background(), Config{DisableKeepalive: true}, conn, wire.TransportQUIC, nil)
	if d != nil || !errors.Is(err, errOpen) {
		t.Fatalf("openDock = %v, %v; want the control open error", d, err)
	}
	if got := conn.abandonedWith(); len(got) != 1 || got[0] != wire.DockCodeProtocol {
		t.Fatalf("connection closes = %v, want one DockCodeProtocol abandon", got)
	}
}

// A predecessor generation with no wire form fails the opening before the
// hello is written, and the error does not reveal the predecessor's
// nonce, which is a succession credential.
func TestOpenDockRefusesUnencodablePredecessorWithoutRevealingNonce(t *testing.T) {
	const nonce = "secret-nonce-value"
	control := &replyStream{reply: bytes.NewReader(nil)}
	conn := newScriptConn(control, nil)
	cfg := Config{DisableKeepalive: true, Predecessor: &dc.DockGen{
		Edge: dc.EdgeTag{Incarnation: "edge-a", LeaseID: "lease-a"},
		Slot: math.MaxUint32 + 1, Epoch: 1, Nonce: nonce,
	}}
	d, err := openDock(context.Background(), cfg, conn, wire.TransportQUIC, nil)
	if d != nil || err == nil {
		t.Fatalf("openDock = %v, %v; want a refusal", d, err)
	}
	if strings.Contains(err.Error(), nonce) {
		t.Fatalf("error %q reveals the predecessor nonce", err)
	}
	if control.hello.Len() != 0 {
		t.Fatalf("hello written (%d bytes) despite the invalid predecessor", control.hello.Len())
	}
	if got := conn.abandonedWith(); len(got) != 1 || got[0] != wire.DockCodeProtocol {
		t.Fatalf("connection closes = %v, want one DockCodeProtocol abandon", got)
	}
}

// A hello that cannot be written fails the opening with the write error
// and abandons the connection.
func TestOpenDockAbandonsConnectionWhenHelloWriteFails(t *testing.T) {
	errWrite := errors.New("hello write failed")
	conn := newScriptConn(&replyStream{reply: bytes.NewReader(nil), writeErr: errWrite}, nil)
	d, err := openDock(context.Background(), Config{DisableKeepalive: true}, conn, wire.TransportQUIC, nil)
	if d != nil || !errors.Is(err, errWrite) {
		t.Fatalf("openDock = %v, %v; want the hello write error", d, err)
	}
	if got := conn.abandonedWith(); len(got) != 1 || got[0] != wire.DockCodeProtocol {
		t.Fatalf("connection closes = %v, want one DockCodeProtocol abandon", got)
	}
}

// Cancellation that lands after the welcome has been read, but before the
// dock is returned, still wins: Open returns the cancellation and no
// dock, and the connection is abandoned, so a caller that gave up never
// receives a live dock it does not expect.
func TestOpenDockCancellationAfterWelcomeReturnsNoDock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	control := &replyStream{reply: bytes.NewReader(welcomeBytes(t, 20_000)), afterReply: cancel}
	conn := newScriptConn(control, nil)
	d, err := openDock(ctx, Config{DisableKeepalive: true}, conn, wire.TransportQUIC, nil)
	if d != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("openDock = %v, %v; want the cancellation and no dock", d, err)
	}
	if conn.Context().Err() == nil {
		t.Fatal("the canceled opening left its connection open")
	}
}

// A welcome without a generation is not a welcome: the edge must assign
// one, so the opening fails and the connection is abandoned.
func TestOpenDockRefusesWelcomeWithoutGeneration(t *testing.T) {
	var b bytes.Buffer
	if err := wire.WriteFrame(&b, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_Welcome{Welcome: &dockpb.DockWelcome{KeepaliveMs: 1}}}); err != nil {
		t.Fatal(err)
	}
	conn := newScriptConn(&replyStream{reply: bytes.NewReader(b.Bytes())}, nil)
	d, err := openDock(context.Background(), Config{DisableKeepalive: true}, conn, wire.TransportQUIC, nil)
	if d != nil || err == nil {
		t.Fatalf("openDock = %v, %v; want a refusal", d, err)
	}
	if got := conn.abandonedWith(); len(got) != 1 || got[0] != wire.DockCodeProtocol {
		t.Fatalf("connection closes = %v, want one DockCodeProtocol abandon", got)
	}
}

// signerFunc is an Ed25519-keyed crypto.Signer whose Sign is scripted.
type signerFunc struct {
	public ed25519.PublicKey
	sign   func([]byte) ([]byte, error)
}

func (s signerFunc) Public() crypto.PublicKey { return s.public }
func (s signerFunc) Sign(_ io.Reader, msg []byte, _ crypto.SignerOpts) ([]byte, error) {
	return s.sign(msg)
}

// exporterConn returns a scripted TLS exporter result.
type exporterConn struct {
	openingConn
	value []byte
	err   error
}

func (c *exporterConn) ExportKeyingMaterial(string, []byte, int) ([]byte, error) {
	return c.value, c.err
}

// Every step of building a dock/3 hello is checked before a byte is
// written: the TLS exporter, the proof input, the signature and the
// client's own verification of that signature. A failure at any step
// writes nothing, so a broken signer can never put a bad proof on the
// wire.
func TestDock3OpeningWritesNothingWhenAnyProofStepFails(t *testing.T) {
	pki := newTestPKI(t)
	lease := testNodeLease(t, time.Now())
	key := pki.clientCert.PrivateKey.(ed25519.PrivateKey)
	public := key.Public().(ed25519.PublicKey)
	goodExporter := testExporter(admissionpb.TLSExporterBytes)
	errExport := errors.New("exporter unavailable")
	errSign := errors.New("signer unavailable")

	cases := map[string]struct {
		exporter    []byte
		exporterErr error
		sign        func([]byte) ([]byte, error)
		is          error
	}{
		"exporter error": {nil, errExport, nil, errExport},
		"short exporter": {goodExporter[:admissionpb.TLSExporterBytes-1], nil, nil, wire.ErrAdmissionMalformed},
		"signer error": {goodExporter, nil, func([]byte) ([]byte, error) {
			return nil, errSign
		}, errSign},
		"wrong signature": {goodExporter, nil, func([]byte) ([]byte, error) {
			return make([]byte, ed25519.SignatureSize), nil
		}, nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			sign := tc.sign
			if sign == nil {
				sign = func(m []byte) ([]byte, error) { return ed25519.Sign(key, m), nil }
			}
			cfg := pki.clientConfig()
			cfg.Admission = &DemandAdmission{LeaseEnvelope: lease, Signer: signerFunc{public: public, sign: sign}}
			stream := &openingStream{}
			conn := &exporterConn{value: tc.exporter, err: tc.exporterErr}
			err := writeDockOpening(stream, conn, cfg, nil, public)
			if err == nil {
				t.Fatal("writeDockOpening succeeded")
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("writeDockOpening = %v, want %v", err, tc.is)
			}
			if stream.Len() != 0 {
				t.Fatalf("%d bytes written despite the failure", stream.Len())
			}
		})
	}
}

// keepaliveConn counts keepalive sends and can fail them.
type keepaliveConn struct {
	scriptConn
	sends   chan time.Time
	failing atomic.Bool
}

func (c *keepaliveConn) SendKeepalive() error {
	c.sends <- time.Now()
	if c.failing.Load() {
		return errors.New("send failed")
	}
	return nil
}

func newKeepaliveConn() *keepaliveConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &keepaliveConn{scriptConn: scriptConn{ctx: ctx, cancel: cancel}, sends: make(chan time.Time, 16)}
}

// The keepalive loop sends one unit of transport activity per jittered
// interval and never later than 80% of the granted cadence, keeps sending
// while sends succeed, and stops at the first failed send.
func TestKeepaliveLoopSendsBeforeGrantAndStopsOnSendFailure(t *testing.T) {
	const granted = 40 * time.Millisecond
	conn := newKeepaliveConn()
	defer conn.cancel()
	d := &Dock{conn: conn, grantedKeepalive: granted}
	done := make(chan struct{})
	start := time.Now()
	go func() { d.keepaliveLoop(); close(done) }()

	prev := start
	for i := 0; i < 3; i++ {
		select {
		case at := <-conn.sends:
			if gap := at.Sub(prev); gap < granted*keepaliveJitterFloorPct/100 {
				t.Fatalf("keepalive %d after %s, before the jitter floor", i, gap)
			}
			prev = at
		case <-time.After(5 * time.Second):
			t.Fatalf("keepalive %d never sent", i)
		}
	}
	conn.failing.Store(true)
	<-conn.sends
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("keepalive loop kept running after a failed send")
	}
}

// The keepalive loop ends with its connection, including when the edge
// granted no cadence and the loop fell back to its default interval.
func TestKeepaliveLoopEndsWithConnection(t *testing.T) {
	conn := newKeepaliveConn()
	d := &Dock{conn: conn} // no grant: the default interval applies
	done := make(chan struct{})
	go func() { d.keepaliveLoop(); close(done) }()
	conn.cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("keepalive loop outlived its connection")
	}
	select {
	case <-conn.sends:
		t.Fatal("a keepalive was sent within the default interval")
	default:
	}
}
