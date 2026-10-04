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
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/proto"

	"github.com/idyl-labs/hyperplane-go/wire"
	commonpb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
	dpb "github.com/idyl-labs/hyperplane-go/wire/deliveryv2"
	dockpb "github.com/idyl-labs/hyperplane-go/wire/dockv2"
	dockv3pb "github.com/idyl-labs/hyperplane-go/wire/dockv3"
	"github.com/idyl-labs/hyperplane-go/wire/fallback"
)

// dock_edge_test.go: the exported dock surface against a scripted edge
// over real QUIC and real TCP+TLS fallback connections on loopback. The
// scripted edge accepts a connection, reads the hello on the control
// stream and answers with the reply each test chooses; afterwards the
// test drives the edge's half of the connection directly.

// edgeTransports names the two transports every end-to-end case runs on.
var edgeTransports = []string{wire.TransportQUIC, wire.TransportTCPFallback}

// scriptedEdge is one loopback edge listener on one transport.
type scriptedEdge struct {
	t         *testing.T
	pki       *testPKI
	transport string
	endpoint  string
	accepted  atomic.Int32
	conns     chan *edgeSession
	ctx       context.Context
}

// edgeSession is the edge's half of one accepted connection.
type edgeSession struct {
	quic    *quic.Conn     // set on QUIC
	mux     *fallback.Conn // set on the fallback
	control io.ReadWriter
	hello   []byte // the client's opening frame body
}

// newScriptedEdge starts an edge on transport. reply answers each hello;
// the session is then handed to the test on conns.
func newScriptedEdge(t *testing.T, pki *testPKI, transport string, reply func(*edgeSession) error) *scriptedEdge {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	e := &scriptedEdge{t: t, pki: pki, transport: transport, conns: make(chan *edgeSession, 4), ctx: ctx}
	var mu sync.Mutex
	var closers []func()
	track := func(f func()) {
		mu.Lock()
		closers = append(closers, f)
		mu.Unlock()
	}
	serve := func(s *edgeSession, accept func() (io.ReadWriter, error)) {
		control, err := accept()
		if err != nil {
			return
		}
		s.control = control
		if s.hello, err = wire.ReadRawFrame(control, 0); err != nil {
			return
		}
		if err := reply(s); err != nil {
			return
		}
		e.conns <- s
	}
	serverTLS := &tls.Config{Certificates: []tls.Certificate{pki.serverCert}, MinVersion: tls.VersionTLS13}
	switch transport {
	case wire.TransportQUIC:
		serverTLS.NextProtos = []string{"idyl/2"}
		ln, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{EnableDatagrams: true})
		if err != nil {
			t.Fatalf("quic listen: %v", err)
		}
		track(func() { _ = ln.Close() })
		e.endpoint = ln.Addr().String()
		go func() {
			for {
				conn, err := ln.Accept(ctx)
				if err != nil {
					return
				}
				e.accepted.Add(1)
				track(func() { _ = conn.CloseWithError(0, "edge stopped") })
				go serve(&edgeSession{quic: conn}, func() (io.ReadWriter, error) { return conn.AcceptStream(ctx) })
			}
		}()
	default:
		serverTLS.NextProtos = []string{fallback.ALPN}
		ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
		if err != nil {
			t.Fatalf("fallback listen: %v", err)
		}
		track(func() { _ = ln.Close() })
		e.endpoint = ln.Addr().String()
		go func() {
			for {
				raw, err := ln.Accept()
				if err != nil {
					return
				}
				e.accepted.Add(1)
				track(func() { _ = raw.Close() })
				go func() {
					if err := raw.(*tls.Conn).HandshakeContext(ctx); err != nil {
						_ = raw.Close()
						return
					}
					mux := fallback.Server(raw, 0)
					serve(&edgeSession{mux: mux}, func() (io.ReadWriter, error) { return mux.AcceptStream(ctx) })
				}()
			}
		}()
	}
	t.Cleanup(func() {
		cancel()
		mu.Lock()
		defer mu.Unlock()
		for _, f := range closers {
			f()
		}
	})
	return e
}

// config is a dock/2 client configuration for this edge.
func (e *scriptedEdge) config() Config {
	cfg := e.pki.clientConfig()
	cfg.Endpoint = e.endpoint
	cfg.DisableKeepalive = true
	cfg.ForceFallback = e.transport == wire.TransportTCPFallback
	return cfg
}

// session waits for the next session the edge answered.
func (e *scriptedEdge) session() *edgeSession {
	e.t.Helper()
	select {
	case s := <-e.conns:
		return s
	case <-time.After(10 * time.Second):
		e.t.Fatal("the edge answered no hello")
		return nil
	}
}

// open opens a dock against this edge and returns it with the edge's
// session.
func (e *scriptedEdge) open(cfg Config) (*Dock, *edgeSession) {
	e.t.Helper()
	d, err := Open(laneCtx(e.t), cfg)
	if err != nil {
		e.t.Fatalf("Open over %s: %v", e.transport, err)
	}
	e.t.Cleanup(func() { _ = d.Abandon() })
	return d, e.session()
}

var edgeGen = &commonpb.DockGen{
	Edge: &commonpb.EdgeTag{Incarnation: []byte("edge-a"), LeaseId: []byte("lease-a")},
	Slot: 5, SlotEpoch: 2, Nonce: []byte("nonce-000005"),
}

// welcome answers with a welcome granting keepaliveMs.
func welcome(keepaliveMs uint32) func(*edgeSession) error {
	return func(s *edgeSession) error {
		return wire.WriteFrame(s.control, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_Welcome{Welcome: &dockpb.DockWelcome{
			Gen: edgeGen, KeepaliveMs: keepaliveMs,
		}}})
	}
}

// closeConn ends the edge's connection with a dock application code.
func (s *edgeSession) closeConn(code uint64, reason string) {
	if s.quic != nil {
		_ = s.quic.CloseWithError(quic.ApplicationErrorCode(code), reason)
		return
	}
	_ = s.mux.CloseWithError(code, reason)
}

// done is the edge connection's end.
func (s *edgeSession) done() <-chan struct{} {
	if s.quic != nil {
		return s.quic.Context().Done()
	}
	return s.mux.Context().Done()
}

// closeCode reports the application code the connection ended with.
func (s *edgeSession) closeCode() (uint64, bool) {
	var cause error
	if s.quic != nil {
		cause = context.Cause(s.quic.Context())
		var app *quic.ApplicationError
		if errors.As(cause, &app) {
			return uint64(app.ErrorCode), true
		}
		return 0, false
	}
	cause = context.Cause(s.mux.Context())
	var ce *fallback.ConnError
	if errors.As(cause, &ce) {
		return ce.Code, true
	}
	return 0, false
}

type edgeBidi interface {
	io.Reader
	io.Writer
	Close() error
}

// openStream opens an edge-initiated bidirectional stream toward the dock.
func (s *edgeSession) openStream(ctx context.Context) (edgeBidi, error) {
	if s.quic != nil {
		return s.quic.OpenStreamSync(ctx)
	}
	return s.mux.OpenStreamSync(ctx)
}

// acceptStream accepts a dock-opened bidirectional stream.
func (s *edgeSession) acceptStream(ctx context.Context) (edgeBidi, error) {
	if s.quic != nil {
		return s.quic.AcceptStream(ctx)
	}
	return s.mux.AcceptStream(ctx)
}

// pushEvent opens a unidirectional stream, writes raw and closes it.
func (s *edgeSession) pushEvent(ctx context.Context, raw []byte) (io.WriteCloser, error) {
	var w io.WriteCloser
	var err error
	if s.quic != nil {
		w, err = s.quic.OpenUniStreamSync(ctx)
	} else {
		w, err = s.mux.OpenUniStream()
	}
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(raw); err != nil {
		return nil, err
	}
	return w, nil
}

func (s *edgeSession) sendControl(t *testing.T, m *dockpb.EdgeToClient) {
	t.Helper()
	if err := wire.WriteFrame(s.control, m); err != nil {
		t.Fatalf("control frame: %v", err)
	}
}

// Open over each transport returns a dock that reports what the edge
// granted and the transport it uses; its hello is a clean dock/2 hello
// that names the requested cadence and the predecessor; and Close ends the
// connection with the drain code, which ends the dock's context.
func TestOpenReportsWelcomeAndClosesWithDrainCode(t *testing.T) {
	for _, transport := range edgeTransports {
		t.Run(transport, func(t *testing.T) {
			edge := newScriptedEdge(t, newTestPKI(t), transport, welcome(12_000))
			cfg := edge.config()
			cfg.KeepaliveMs = 9_000
			gen := wire.GenFromProtoV2(edgeGen)
			cfg.Predecessor = &gen
			d, s := edge.open(cfg)

			if d.Gen() != wire.GenFromProtoV2(edgeGen) {
				t.Fatal("Gen differs from the generation the edge assigned")
			}
			if d.Keepalive() != 12*time.Second {
				t.Fatalf("Keepalive = %s, want the granted 12s", d.Keepalive())
			}
			if d.Transport() != transport {
				t.Fatalf("Transport = %q, want %q", d.Transport(), transport)
			}
			if d.Resumed() {
				t.Fatal("a first dock without a session cache reports a resumed session")
			}

			var hello dockpb.ClientToEdge
			if err := proto.Unmarshal(s.hello, &hello); err != nil {
				t.Fatalf("hello: %v", err)
			}
			h := hello.GetHello()
			if h.GetContract() != "dock/2" || h.GetKeepaliveMs() != 9_000 || !proto.Equal(h.GetPredecessorGen(), edgeGen) {
				t.Fatalf("hello = %v, want dock/2 with the requested cadence and the predecessor", h)
			}

			if err := d.Context().Err(); err != nil {
				t.Fatalf("a live dock's context ended: %v", err)
			}
			if err := d.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			<-d.Context().Done()
			select {
			case <-s.done():
			case <-time.After(5 * time.Second):
				t.Fatal("the edge did not see the dock close")
			}
			if code, ok := s.closeCode(); !ok || code != wire.DockCodeDrain {
				t.Fatalf("edge saw close code %#x (application close %v), want DockCodeDrain", code, ok)
			}
		})
	}
}

// An Overloaded frame is the edge's typed refusal: Open returns
// ErrOverloaded with the edge's retry hint on both transports, and never
// tries the other transport, because a refusal is an answer.
func TestOpenOverloadedFrameCarriesRetryHint(t *testing.T) {
	for _, transport := range edgeTransports {
		t.Run(transport, func(t *testing.T) {
			edge := newScriptedEdge(t, newTestPKI(t), transport, func(s *edgeSession) error {
				return wire.WriteFrame(s.control, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_Overloaded{
					Overloaded: &dockpb.DockOverloaded{RetryAfterMs: 2_500},
				}})
			})
			d, err := Open(laneCtx(t), edge.config())
			var over ErrOverloaded
			if d != nil || !errors.As(err, &over) || over.RetryAfter != 2500*time.Millisecond {
				t.Fatalf("Open = %v, %v; want ErrOverloaded with a 2.5s hint", d, err)
			}
			if n := edge.accepted.Load(); n != 1 {
				t.Fatalf("edge accepted %d connections, want 1", n)
			}
		})
	}
}

// A connection closed with the overloaded code before any reply is still
// the typed refusal, without a hint, on both transports.
func TestOpenOverloadedCloseCodeIsTypedRefusalWithoutHint(t *testing.T) {
	for _, transport := range edgeTransports {
		t.Run(transport, func(t *testing.T) {
			edge := newScriptedEdge(t, newTestPKI(t), transport, func(s *edgeSession) error {
				s.closeConn(wire.DockCodeOverloaded, "overloaded")
				return nil
			})
			d, err := Open(laneCtx(t), edge.config())
			var over ErrOverloaded
			if d != nil || !errors.As(err, &over) || over.RetryAfter != 0 {
				t.Fatalf("Open = %v, %v; want ErrOverloaded without a hint", d, err)
			}
		})
	}
}

// Any other close before the welcome is a failed opening that is not
// classified as overload.
func TestOpenOtherCloseBeforeWelcomeIsNotOverload(t *testing.T) {
	for _, transport := range edgeTransports {
		t.Run(transport, func(t *testing.T) {
			edge := newScriptedEdge(t, newTestPKI(t), transport, func(s *edgeSession) error {
				s.closeConn(wire.DockCodeBadCert, "bad certificate")
				return nil
			})
			d, err := Open(laneCtx(t), edge.config())
			var over ErrOverloaded
			if d != nil || err == nil || errors.As(err, &over) {
				t.Fatalf("Open = %v, %v; want a failure that is not ErrOverloaded", d, err)
			}
		})
	}
}

// A dock/3 attempt the edge refuses is reported as an error and is never
// retried as dock/2: the edge sees exactly one connection, and its hello
// was the dock/3 form.
func TestOpenDock3RefusalIsNeverRetriedAsDock2(t *testing.T) {
	for _, transport := range edgeTransports {
		t.Run(transport, func(t *testing.T) {
			pki := newTestPKI(t)
			hellos := make(chan []byte, 4)
			edge := newScriptedEdge(t, pki, transport, func(s *edgeSession) error {
				hellos <- s.hello
				s.closeConn(wire.DockCodeProtocol, "refused")
				return nil
			})
			cfg := edge.config()
			cfg.Admission = &DemandAdmission{
				LeaseEnvelope: testNodeLease(t, time.Now()),
				Signer:        pki.clientCert.PrivateKey.(ed25519.PrivateKey),
			}
			if d, err := Open(laneCtx(t), cfg); d != nil || err == nil {
				t.Fatalf("Open = %v, %v; want the edge's refusal", d, err)
			}
			if n := edge.accepted.Load(); n != 1 {
				t.Fatalf("edge accepted %d connections, want exactly 1", n)
			}
			var hello dockv3pb.ClientToEdge
			if err := proto.Unmarshal(<-hellos, &hello); err != nil {
				t.Fatalf("hello: %v", err)
			}
			if hello.GetHello().GetContract() != dockv3pb.Contract {
				t.Fatalf("hello contract = %q, want %q", hello.GetHello().GetContract(), dockv3pb.Contract)
			}
		})
	}
}

// On QUIC the keepalive is the single datagram byte 0x00 and it arrives
// before the granted cadence elapses, so one keepalive per interval keeps
// the edge's idle detection quiet.
func TestQUICKeepaliveIsSingleZeroByteDatagram(t *testing.T) {
	edge := newScriptedEdge(t, newTestPKI(t), wire.TransportQUIC, welcome(50))
	cfg := edge.config()
	cfg.DisableKeepalive = false
	_, s := edge.open(cfg)
	for i := 0; i < 2; i++ {
		dg, err := s.quic.ReceiveDatagram(laneCtx(t))
		if err != nil {
			t.Fatalf("ReceiveDatagram: %v", err)
		}
		if !bytes.Equal(dg, wire.LaneKeepalive()) {
			t.Fatalf("keepalive datagram = %x, want 00", dg)
		}
	}
}

// On the fallback the keepalive is a PING frame. An edge with a short idle
// window keeps a dock that sends keepalives, and ends one whose keepalives
// are disabled: the negative control shows the window is real.
func TestFallbackKeepaliveHoldsEdgeIdleWindowOpen(t *testing.T) {
	const idle = 500 * time.Millisecond
	pki := newTestPKI(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{pki.serverCert}, NextProtos: []string{fallback.ALPN}, MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				// Finish the TLS handshake before the idle window starts, so
				// the window measures only dock traffic, however slow the
				// handshake is on a loaded machine.
				hctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				err := raw.(*tls.Conn).HandshakeContext(hctx)
				cancel()
				if err != nil {
					_ = raw.Close()
					return
				}
				mux := fallback.Server(raw, idle)
				s, err := mux.AcceptStream(context.Background())
				if err != nil {
					return
				}
				if _, err := wire.ReadRawFrame(s, 0); err != nil {
					return
				}
				_ = welcome(30)(&edgeSession{control: s})
			}()
		}
	}()

	open := func(disable bool) *Dock {
		cfg := pki.clientConfig()
		cfg.Endpoint, cfg.ForceFallback, cfg.DisableKeepalive = ln.Addr().String(), true, disable
		d, err := Open(laneCtx(t), cfg)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		t.Cleanup(func() { _ = d.Abandon() })
		return d
	}

	silent := open(true)
	select {
	case <-silent.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("negative control: the edge never idled out a dock without keepalives")
	}

	live := open(false)
	select {
	case <-live.Context().Done():
		t.Fatalf("the edge idled out a dock sending keepalives: %v", context.Cause(live.Context()))
	case <-time.After(3 * idle):
	}
}

// Pushed events arrive over both transports, and a malformed push is
// refused by resetting that stream: the edge's next write on it fails
// with DockCodeProtocol.
func TestEventsOverBothTransports(t *testing.T) {
	for _, transport := range edgeTransports {
		t.Run(transport, func(t *testing.T) {
			edge := newScriptedEdge(t, newTestPKI(t), transport, welcome(20_000))
			d, s := edge.open(edge.config())
			ctx := laneCtx(t)

			w, err := s.pushEvent(ctx, eventFrame(t, []byte("event-c")))
			if err != nil {
				t.Fatalf("push: %v", err)
			}
			_ = w.Close()
			payload, err := d.AcceptEvent(ctx)
			if err != nil || string(payload) != "event-c" {
				t.Fatalf("AcceptEvent = %q, %v", payload, err)
			}

			bad, err := s.pushEvent(ctx, []byte{0x00, 0x20, 0x00, 0x00})
			if err != nil {
				t.Fatalf("push: %v", err)
			}
			if _, err := d.AcceptEvent(ctx); !errors.Is(err, wire.ErrFrameTooLarge) {
				t.Fatalf("AcceptEvent on a malformed push = %v, want ErrFrameTooLarge", err)
			}
			code, err := writeUntilReset(ctx, bad)
			if err != nil {
				t.Fatalf("the refused push was not reset: %v", err)
			}
			if code != wire.DockCodeProtocol {
				t.Fatalf("refused push reset with %#x, want DockCodeProtocol", code)
			}
		})
	}
}

// writeUntilReset writes to w until the peer's reset surfaces, and
// returns its code.
func writeUntilReset(ctx context.Context, w io.Writer) (uint64, error) {
	chunk := make([]byte, 1024)
	for ctx.Err() == nil {
		_, err := w.Write(chunk)
		if err == nil {
			continue
		}
		var qe *quic.StreamError
		if errors.As(err, &qe) {
			return uint64(qe.ErrorCode), nil
		}
		var fe fallback.StreamResetError
		if errors.As(err, &fe) {
			return fe.Code, nil
		}
		return 0, err
	}
	return 0, ctx.Err()
}

// readUntilReset reads r until the peer's reset surfaces, and returns its
// code.
func readUntilReset(r io.Reader) (uint64, error) {
	_, err := io.Copy(io.Discard, r)
	var qe *quic.StreamError
	if errors.As(err, &qe) {
		return uint64(qe.ErrorCode), nil
	}
	var fe fallback.StreamResetError
	if errors.As(err, &fe) {
		return fe.Code, nil
	}
	return 0, errors.New("stream ended without a reset")
}

// Lanes, lane streams in both directions and RPCs share one dock on both
// transports: the edge attaches a lane and opens an attributed stream and
// an RPC; the dock opens a stream on the lane, whose attribution the edge
// reads first; an aborted lane stream reaches the edge as a
// DockCodeProtocol reset; LaneClosed ends the lane with its cause; and
// once the connection ends every accept and open reports it.
func TestLanesAndRPCsShareOneDockOverBothTransports(t *testing.T) {
	for _, transport := range edgeTransports {
		t.Run(transport, func(t *testing.T) {
			edge := newScriptedEdge(t, newTestPKI(t), transport, welcome(20_000))
			d, s := edge.open(edge.config())
			ctx := laneCtx(t)

			s.sendControl(t, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_LaneAttached{LaneAttached: &dockpb.LaneAttached{
				LaneId: 11, PeerPrincipal: "spiffe://example.com/node-a", LaneClass: wire.LaneClassStream, Metadata: []byte("m"),
			}}})
			lane, err := d.AcceptLane(ctx)
			if err != nil {
				t.Fatalf("AcceptLane: %v", err)
			}

			// Edge-opened lane stream: attribution, then payload.
			in, err := s.openStream(ctx)
			if err != nil {
				t.Fatalf("edge open: %v", err)
			}
			attr, err := wire.AppendLaneHeader(nil, wire.LaneStreamHeader{LaneID: 11, Class: wire.LaneStreamClassPassthrough, Header: []byte("pod-a")})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := in.Write(append(attr, "hello"...)); err != nil {
				t.Fatalf("edge write: %v", err)
			}
			_ = in.Close()
			ls, err := lane.AcceptStream(ctx)
			if err != nil {
				t.Fatalf("AcceptStream: %v", err)
			}
			if ls.Class() != wire.LaneStreamClassPassthrough || string(ls.Header()) != "pod-a" {
				t.Fatalf("accepted stream class %#x header %q", ls.Class(), ls.Header())
			}
			if body, err := io.ReadAll(ls); err != nil || string(body) != "hello" {
				t.Fatalf("lane stream read = %q, %v", body, err)
			}
			if _, err := ls.Write([]byte("bye")); err != nil {
				t.Fatalf("lane stream write: %v", err)
			}
			_ = ls.Close()
			if reply, err := io.ReadAll(in); err != nil || string(reply) != "bye" {
				t.Fatalf("edge read = %q, %v", reply, err)
			}

			// Edge-opened RPC on the same dock.
			rpcStream, err := s.openStream(ctx)
			if err != nil {
				t.Fatalf("edge open: %v", err)
			}
			if err := wire.WriteFrame(rpcStream, &dpb.RpcOpen{Metadata: []byte(ReportRPCMetadata)}); err != nil {
				t.Fatalf("rpc open: %v", err)
			}
			md, rpc, err := d.AcceptRPC(ctx)
			if err != nil || string(md) != ReportRPCMetadata {
				t.Fatalf("AcceptRPC = %q, %v", md, err)
			}
			rpc.Abort()
			if code, err := readUntilReset(rpcStream); err != nil || code != wire.DockCodeProtocol {
				t.Fatalf("aborted RPC reached the edge as %#x, %v; want a DockCodeProtocol reset", code, err)
			}

			// Dock-opened lane stream: the edge reads the attribution first.
			out, err := lane.OpenStream(ctx, wire.LaneStreamClassE2EMTLS, []byte("hdr"))
			if err != nil {
				t.Fatalf("OpenStream: %v", err)
			}
			if _, err := out.Write([]byte("x")); err != nil {
				t.Fatalf("write: %v", err)
			}
			acc, err := s.acceptStream(ctx)
			if err != nil {
				t.Fatalf("edge accept: %v", err)
			}
			h, err := readKindAndHeader(acc)
			if err != nil || h.LaneID != 11 || h.Class != wire.LaneStreamClassE2EMTLS || string(h.Header) != "hdr" {
				t.Fatalf("edge read attribution %+v, %v", h, err)
			}
			out.Abort()
			if code, err := readUntilReset(acc); err != nil || code != wire.DockCodeProtocol {
				t.Fatalf("aborted lane stream reached the edge as %#x, %v; want a DockCodeProtocol reset", code, err)
			}

			// A second lane stays live while the first is closed.
			s.sendControl(t, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_LaneAttached{LaneAttached: &dockpb.LaneAttached{
				LaneId: 12, LaneClass: wire.LaneClassStream,
			}}})
			second, err := d.AcceptLane(ctx)
			if err != nil {
				t.Fatalf("AcceptLane: %v", err)
			}
			s.sendControl(t, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_LaneClosed{LaneClosed: &dockpb.LaneClosed{
				LaneId: 11, Cause: dockpb.LaneCloseCause_LANE_CLOSE_CAUSE_DRAINED,
			}}})
			select {
			case <-lane.Closed():
			case <-ctx.Done():
				t.Fatal("LaneClosed did not end the lane")
			}
			if lane.CloseCause() != dockpb.LaneCloseCause_LANE_CLOSE_CAUSE_DRAINED {
				t.Fatalf("CloseCause = %v", lane.CloseCause())
			}

			// The connection ends: every accept and open reports it.
			s.closeConn(wire.DockCodeDrain, "edge restart")
			<-d.Context().Done()
			if _, err := d.AcceptLane(ctx); err == nil {
				t.Fatal("AcceptLane succeeded on an ended dock")
			}
			if _, _, err := d.AcceptRPC(ctx); err == nil {
				t.Fatal("AcceptRPC succeeded on an ended dock")
			}
			if _, err := d.AcceptEvent(ctx); err == nil {
				t.Fatal("AcceptEvent succeeded on an ended dock")
			}
			if _, err := second.OpenStream(ctx, wire.LaneStreamClassPassthrough, nil); err == nil {
				t.Fatal("OpenStream succeeded on an ended dock")
			}
		})
	}
}

// An inbound stream with an unassigned kind byte is refused over the real
// transports with a DockCodeProtocol reset that the edge observes.
func TestUnknownStreamKindResetOverBothTransports(t *testing.T) {
	for _, transport := range edgeTransports {
		t.Run(transport, func(t *testing.T) {
			edge := newScriptedEdge(t, newTestPKI(t), transport, welcome(20_000))
			d, s := edge.open(edge.config())
			ctx := laneCtx(t)
			go func() { _, _ = d.AcceptLane(ctx) }() // starts inbound dispatch
			st, err := s.openStream(ctx)
			if err != nil {
				t.Fatalf("edge open: %v", err)
			}
			if _, err := st.Write([]byte{0x7f}); err != nil {
				t.Fatalf("edge write: %v", err)
			}
			if code, err := readUntilReset(st); err != nil || code != wire.DockCodeProtocol {
				t.Fatalf("unknown kind reset with %#x, %v; want DockCodeProtocol", code, err)
			}
		})
	}
}

// Abandon ends the dock without the graceful drain: on QUIC the edge sees
// DockCodeProtocol, on the fallback the TCP connection drops. A second
// Abandon is harmless on both.
func TestAbandonEndsDockAbruptlyAndIsIdempotent(t *testing.T) {
	for _, transport := range edgeTransports {
		t.Run(transport, func(t *testing.T) {
			edge := newScriptedEdge(t, newTestPKI(t), transport, welcome(20_000))
			d, s := edge.open(edge.config())
			if err := d.Abandon(); err != nil {
				t.Fatalf("Abandon: %v", err)
			}
			<-d.Context().Done()
			select {
			case <-s.done():
			case <-time.After(5 * time.Second):
				t.Fatal("the edge did not see the abandoned dock end")
			}
			code, app := s.closeCode()
			switch transport {
			case wire.TransportQUIC:
				if !app || code != wire.DockCodeProtocol {
					t.Fatalf("edge saw %#x (application close %v), want DockCodeProtocol", code, app)
				}
			default:
				if app {
					t.Fatalf("edge saw a graceful CLOSE frame (%#x) from an abandoned fallback dock", code)
				}
			}
			if err := d.Abandon(); err != nil {
				t.Fatalf("second Abandon: %v", err)
			}
		})
	}
}

// Flows round-trip over real QUIC: the edge reads the dock's datagram
// with its attribution prefix, and a datagram the edge sends with the
// dock's lane id arrives on that lane with its flow id and payload.
func TestFlowsOverQUIC(t *testing.T) {
	edge := newScriptedEdge(t, newTestPKI(t), wire.TransportQUIC, welcome(20_000))
	d, s := edge.open(edge.config())
	ctx := laneCtx(t)

	s.sendControl(t, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_LaneAttached{LaneAttached: &dockpb.LaneAttached{
		LaneId: 21, LaneClass: wire.LaneClassStream | wire.LaneClassFlow,
	}}})
	lane, err := d.AcceptLane(ctx)
	if err != nil {
		t.Fatalf("AcceptLane: %v", err)
	}

	if err := lane.SendFlow(300, []byte("ping")); err != nil {
		t.Fatalf("SendFlow: %v", err)
	}
	dg, err := s.quic.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatalf("edge ReceiveDatagram: %v", err)
	}
	if want := []byte{21, 0xAC, 0x02, 'p', 'i', 'n', 'g'}; !bytes.Equal(dg, want) {
		t.Fatalf("edge received %x, want %x", dg, want)
	}

	if err := s.quic.SendDatagram([]byte{21, 0x07, 'p', 'o', 'n', 'g'}); err != nil {
		t.Fatalf("edge SendDatagram: %v", err)
	}
	flowID, payload, err := lane.ReceiveFlow(ctx)
	if err != nil || flowID != 7 || string(payload) != "pong" {
		t.Fatalf("ReceiveFlow = (%d, %q, %v), want (7, \"pong\")", flowID, payload, err)
	}
}

// The fallback has no datagram plane, so a flow lane on a fallback dock
// refuses SendFlow locally rather than claiming a send.
func TestFlowsRefusedOverFallback(t *testing.T) {
	edge := newScriptedEdge(t, newTestPKI(t), wire.TransportTCPFallback, welcome(20_000))
	d, s := edge.open(edge.config())
	s.sendControl(t, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_LaneAttached{LaneAttached: &dockpb.LaneAttached{
		LaneId: 22, LaneClass: wire.LaneClassFlow,
	}}})
	lane, err := d.AcceptLane(laneCtx(t))
	if err != nil {
		t.Fatalf("AcceptLane: %v", err)
	}
	if err := lane.SendFlow(1, []byte("x")); !errors.Is(err, ErrFlowClassNotGranted) {
		t.Fatalf("SendFlow over the fallback = %v, want ErrFlowClassNotGranted", err)
	}
}

// OpenStream carries a caller-defined exchange over both transports: the
// edge reads exactly the caller's bytes, the reply reaches the caller,
// and FIN in both directions finishes the stream without a reset. A
// stream wrapped by NewRPC and aborted reaches the edge as a
// DockCodeProtocol reset.
func TestOpenStreamOverBothTransports(t *testing.T) {
	for _, transport := range edgeTransports {
		t.Run(transport, func(t *testing.T) {
			edge := newScriptedEdge(t, newTestPKI(t), transport, welcome(20_000))
			d, s := edge.open(edge.config())
			ctx := laneCtx(t)

			out, err := d.OpenStream(ctx)
			if err != nil {
				t.Fatalf("OpenStream: %v", err)
			}
			if _, err := out.Write([]byte{0x7f, 'r', 'e', 'q'}); err != nil {
				t.Fatalf("write: %v", err)
			}
			if err := out.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			in, err := s.acceptStream(ctx)
			if err != nil {
				t.Fatalf("edge accept: %v", err)
			}
			if got, err := io.ReadAll(in); err != nil || string(got) != "\x7freq" {
				t.Fatalf("edge read = %q, %v; want the caller's bytes then FIN", got, err)
			}
			if _, err := in.Write([]byte("resp")); err != nil {
				t.Fatalf("edge write: %v", err)
			}
			_ = in.Close()
			if got, err := io.ReadAll(out); err != nil || string(got) != "resp" {
				t.Fatalf("stream read = %q, %v; want the reply then FIN", got, err)
			}

			rs, err := d.OpenStream(ctx)
			if err != nil {
				t.Fatalf("second OpenStream: %v", err)
			}
			if _, err := rs.Write([]byte{0x7f}); err != nil {
				t.Fatalf("write: %v", err)
			}
			acc, err := s.acceptStream(ctx)
			if err != nil {
				t.Fatalf("edge accept: %v", err)
			}
			NewRPC(rs).Abort()
			if code, err := readUntilReset(acc); err != nil || code != wire.DockCodeProtocol {
				t.Fatalf("aborted RPC reached the edge as %#x, %v; want a DockCodeProtocol reset", code, err)
			}

			s.closeConn(wire.DockCodeDrain, "edge restart")
			<-d.Context().Done()
			if _, err := d.OpenStream(ctx); err == nil {
				t.Fatal("OpenStream succeeded on an ended dock")
			}
		})
	}
}

// FinishStream over both transports: when the edge finishes its direction
// the stream ends without a reset, and when the edge never does, the
// bounded drain resets it and the edge observes DockCodeProtocol.
func TestFinishStreamOverBothTransports(t *testing.T) {
	old := drainTimeout
	drainTimeout = 200 * time.Millisecond
	t.Cleanup(func() { drainTimeout = old })
	for _, transport := range edgeTransports {
		t.Run(transport, func(t *testing.T) {
			edge := newScriptedEdge(t, newTestPKI(t), transport, welcome(20_000))
			d, s := edge.open(edge.config())
			ctx := laneCtx(t)

			done, err := d.OpenStream(ctx)
			if err != nil {
				t.Fatalf("OpenStream: %v", err)
			}
			if _, err := done.Write([]byte{0x7f}); err != nil {
				t.Fatalf("write: %v", err)
			}
			in, err := s.acceptStream(ctx)
			if err != nil {
				t.Fatalf("edge accept: %v", err)
			}
			if _, err := in.Write([]byte("reply")); err != nil {
				t.Fatalf("edge write: %v", err)
			}
			_ = in.Close()
			FinishStream(done)
			if got, err := io.ReadAll(in); err != nil || string(got) != "\x7f" {
				t.Fatalf("edge read = %q, %v; want the request then FIN, no reset", got, err)
			}

			stalled, err := d.OpenStream(ctx)
			if err != nil {
				t.Fatalf("OpenStream: %v", err)
			}
			if _, err := stalled.Write([]byte{0x7f}); err != nil {
				t.Fatalf("write: %v", err)
			}
			held, err := s.acceptStream(ctx)
			if err != nil {
				t.Fatalf("edge accept: %v", err)
			}
			FinishStream(stalled)
			if code, err := writeUntilReset(ctx, held); err != nil || code != wire.DockCodeProtocol {
				t.Fatalf("stalled stream reached the edge as %#x, %v; want a DockCodeProtocol reset", code, err)
			}
		})
	}
}

// edgeServeVerb accepts one delivery stream, checks its kind byte, reads
// the verb and writes reply.
func edgeServeVerb(ctx context.Context, t *testing.T, s *edgeSession, reply *dpb.EdgeToRequester) (edgeBidi, *dpb.RequesterToEdge) {
	t.Helper()
	st, err := s.acceptStream(ctx)
	if err != nil {
		t.Fatalf("edge accept: %v", err)
	}
	kind := make([]byte, 1)
	if _, err := io.ReadFull(st, kind); err != nil || kind[0] != wire.StreamKindDelivery {
		t.Fatalf("delivery kind byte = %x, %v", kind, err)
	}
	var verb dpb.RequesterToEdge
	if err := wire.ReadFrame(st, &verb, 0); err != nil {
		t.Fatalf("verb: %v", err)
	}
	if err := wire.WriteFrame(st, reply); err != nil {
		t.Fatalf("reply: %v", err)
	}
	return st, &verb
}

// The three delivery verbs over both transports: SendEvent is
// acknowledged, OpenRPC becomes a byte pipe in both directions, and
// OpenLane returns the lane the edge then attaches.
func TestRequesterVerbsOverBothTransports(t *testing.T) {
	for _, transport := range edgeTransports {
		t.Run(transport, func(t *testing.T) {
			edge := newScriptedEdge(t, newTestPKI(t), transport, welcome(20_000))
			d, s := edge.open(edge.config())
			ctx := laneCtx(t)

			sent := make(chan error, 1)
			go func() { sent <- d.SendEvent(ctx, []byte("loc-a"), []byte("payload")) }()
			st, verb := edgeServeVerb(ctx, t, s, &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_Ack{Ack: &dpb.Ack{}}})
			_ = st.Close()
			if err := <-sent; err != nil {
				t.Fatalf("SendEvent: %v", err)
			}
			if ev := verb.GetSendEvent(); string(ev.GetLocator()) != "loc-a" || string(ev.GetPayload()) != "payload" {
				t.Fatalf("SendEvent verb = %v", verb)
			}

			type opened struct {
				rpc *RPC
				err error
			}
			rpcs := make(chan opened, 1)
			go func() {
				rpc, err := d.OpenRPC(ctx, []byte("loc-b"), []byte(ReportRPCMetadata))
				rpcs <- opened{rpc, err}
			}()
			pipe, verb := edgeServeVerb(ctx, t, s, &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_RpcOpened{RpcOpened: &dpb.RpcOpened{}}})
			o := <-rpcs
			if o.err != nil {
				t.Fatalf("OpenRPC: %v", o.err)
			}
			if string(verb.GetOpenRpc().GetMetadata()) != ReportRPCMetadata {
				t.Fatalf("OpenRPC verb = %v", verb)
			}
			if _, err := o.rpc.Write([]byte("ping")); err != nil {
				t.Fatalf("rpc write: %v", err)
			}
			_ = o.rpc.Close()
			if got, err := io.ReadAll(pipe); err != nil || string(got) != "ping" {
				t.Fatalf("edge read = %q, %v", got, err)
			}
			if _, err := pipe.Write([]byte("pong")); err != nil {
				t.Fatalf("edge write: %v", err)
			}
			_ = pipe.Close()
			if got, err := io.ReadAll(o.rpc); err != nil || string(got) != "pong" {
				t.Fatalf("rpc read = %q, %v", got, err)
			}

			type established struct {
				lane *Lane
				err  error
			}
			lanes := make(chan established, 1)
			go func() {
				lane, _, err := d.OpenLane(ctx, []LaneTarget{{Locator: []byte("loc-c")}}, wire.LaneClassStream, nil)
				lanes <- established{lane, err}
			}()
			st, _ = edgeServeVerb(ctx, t, s, &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_LaneOpened{LaneOpened: &dpb.LaneOpened{
				LaneId: 31, TargetConfirms: []*dpb.LaneTargetConfirm{{Principal: "spiffe://example.com/target"}},
			}}})
			s.sendControl(t, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_LaneAttached{LaneAttached: &dockpb.LaneAttached{
				LaneId: 31, LaneClass: wire.LaneClassStream, PeerPrincipal: "spiffe://example.com/target",
			}}})
			_ = st.Close()
			l := <-lanes
			if l.err != nil || l.lane == nil || l.lane.ID() != 31 {
				t.Fatalf("OpenLane = %v, %v; want lane 31", l.lane, l.err)
			}
		})
	}
}

// runVerb runs one delivery verb and returns its error.
func runVerb(ctx context.Context, d *Dock, verb string) error {
	switch verb {
	case "SendEvent":
		return d.SendEvent(ctx, []byte("loc"), nil)
	case "OpenRPC":
		_, err := d.OpenRPC(ctx, []byte("loc"), nil)
		return err
	default:
		_, _, err := d.OpenLane(ctx, []LaneTarget{{Locator: []byte("loc")}}, wire.LaneClassStream, nil)
		return err
	}
}

// awaitReset waits, with a bound, for the dock to reset st, and fails the
// test unless the reset carries DockCodeProtocol. A stream the dock
// abandons instead would block the edge's writes once their window fills.
func awaitReset(t *testing.T, st edgeBidi) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type result struct {
		code uint64
		err  error
	}
	reset := make(chan result, 1)
	go func() {
		code, err := writeUntilReset(ctx, st)
		reset <- result{code, err}
	}()
	select {
	case r := <-reset:
		if r.err != nil || r.code != wire.DockCodeProtocol {
			t.Fatalf("the edge saw %#x, %v; want a DockCodeProtocol reset", r.code, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the dock never reset the stream; the edge's writes blocked")
	}
}

// readVerb accepts a delivery stream and reads its kind byte and verb.
func readVerb(ctx context.Context, t *testing.T, s *edgeSession) edgeBidi {
	t.Helper()
	st, err := s.acceptStream(ctx)
	if err != nil {
		t.Fatalf("edge accept: %v", err)
	}
	var kind [1]byte
	if _, err := io.ReadFull(st, kind[:]); err != nil {
		t.Fatalf("kind byte: %v", err)
	}
	var verb dpb.RequesterToEdge
	if err := wire.ReadFrame(st, &verb, 0); err != nil {
		t.Fatalf("verb: %v", err)
	}
	return st
}

// Ending the context after a verb is sent, while the edge withholds its
// reply, ends the verb promptly on both transports: it returns an error
// matching context.Canceled, and the edge observes the stream reset with
// DockCodeProtocol.
func TestRequesterVerbsReturnOnCancel(t *testing.T) {
	for _, transport := range edgeTransports {
		for _, verb := range []string{"SendEvent", "OpenRPC", "OpenLane"} {
			t.Run(transport+"/"+verb, func(t *testing.T) {
				edge := newScriptedEdge(t, newTestPKI(t), transport, welcome(20_000))
				d, s := edge.open(edge.config())
				ctx, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)
				done := make(chan error, 1)
				go func() { done <- runVerb(ctx, d, verb) }()

				st := readVerb(laneCtx(t), t, s)
				cancel()
				select {
				case err := <-done:
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("%s = %v, want an error matching context.Canceled", verb, err)
					}
				case <-time.After(5 * time.Second):
					t.Fatalf("%s did not return after its context ended", verb)
				}
				awaitReset(t, st)
			})
		}
	}
}

// After a refusal from an edge that never finishes its direction, the
// bounded drain resets the stream, on both transports and for both
// SendEvent and OpenRPC, so the stream cannot stay half open.
func TestRequesterRefusalResetsPeerThatNeverFinishes(t *testing.T) {
	old := drainTimeout
	drainTimeout = 100 * time.Millisecond
	t.Cleanup(func() { drainTimeout = old })
	for _, transport := range edgeTransports {
		for _, verb := range []string{"SendEvent", "OpenRPC"} {
			t.Run(transport+"/"+verb, func(t *testing.T) {
				edge := newScriptedEdge(t, newTestPKI(t), transport, welcome(20_000))
				d, s := edge.open(edge.config())
				ctx := laneCtx(t)
				done := make(chan error, 1)
				go func() { done <- runVerb(ctx, d, verb) }()

				st := readVerb(ctx, t, s)
				if err := wire.WriteFrame(st, &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_Nak{
					Nak: &dpb.Nak{Code: dpb.NakCode_NAK_CODE_TARGET_GONE},
				}}); err != nil {
					t.Fatalf("reply: %v", err)
				}
				var nak NakError
				if err := <-done; !errors.As(err, &nak) || nak.Code != dpb.NakCode_NAK_CODE_TARGET_GONE {
					t.Fatalf("%s = %v, want NakError NAK_CODE_TARGET_GONE", verb, err)
				}
				awaitReset(t, st)
			})
		}
	}
}
