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
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	dc "github.com/idyl-labs/hyperplane-go/generation"
	"github.com/idyl-labs/hyperplane-go/wire"
	admissionpb "github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	pb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
	dockpb "github.com/idyl-labs/hyperplane-go/wire/dockv2"
	dockv3pb "github.com/idyl-labs/hyperplane-go/wire/dockv3"
	"github.com/idyl-labs/hyperplane-go/wire/fallback"
)

// DemandAdmission is the complete client-held material for one dock/3
// attempt. LeaseEnvelope is transmitted byte-for-byte. Signer must be the
// Ed25519 private key belonging to Config.SVID's leaf SVID; it signs a
// fresh proof bound to this attempt's TLS exporter.
type DemandAdmission struct {
	LeaseEnvelope []byte
	Signer        crypto.Signer
}

// Config parameterizes one dock attempt.
type Config struct {
	// Endpoint is the edge's UDP address (host:port).
	Endpoint string
	// ServerID is the exact SPIFFE ID expected from the fabric edge.
	ServerID spiffeid.ID
	// SVID is the client's leaf+intermediate chain and key.
	SVID tls.Certificate
	// Bundles authenticates the edge's SPIFFE SVID trust domain.
	Bundles x509bundle.Source
	// Admission selects the hello form. Nil selects dock/2; non-nil selects
	// dock/3 and supplies its lease and proof signer. An invalid dock/3
	// opening fails locally, and a dock/3 attempt is never retried as
	// dock/2.
	Admission *DemandAdmission

	// Predecessor names the client's previous generation, as reported by
	// the previous dock's Gen, and makes this dock a succession of it. Nil
	// for a first dock or for a client that does not hold its previous
	// generation (for example after a restart).
	Predecessor *dc.DockGen

	// KeepaliveMs is the requested keepalive cadence in milliseconds; 0
	// lets the edge choose. After the handshake the dock sends transport
	// activity (a datagram on QUIC, a PING frame on the fallback) at a
	// jittered interval below the cadence the edge granted.
	KeepaliveMs uint32

	// DisableKeepalive turns off all keepalive traffic from the client, so
	// a silent dock is detected only by the edge's idle timeout. It is for
	// tests and diagnostics of that path; ordinary clients leave it unset
	// so that their NAT bindings stay alive.
	DisableKeepalive bool

	// SessionCache enables TLS session resumption across docks: session
	// tickets from the edge are stored here, and later docks that resume
	// skip the certificate exchange, which makes reconnecting cheaper.
	// Share one cache across a client's docks (for example
	// tls.NewLRUClientSessionCache). Nil makes every dock a full
	// handshake.
	SessionCache tls.ClientSessionCache

	// LocalIP binds the dock's source address (the UDP socket on QUIC,
	// the TCP dialer on the fallback) to a specific local IP. Empty lets
	// the operating system choose. A host that opens many docks can spread
	// them across several source IPs to stay under the ephemeral-port
	// limit for one source and destination pair. Each dock still uses its
	// own socket and source port.
	LocalIP string

	// MaxStreamReceiveWindow and MaxConnectionReceiveWindow set the
	// dock's QUIC flow-control ceilings: the per-stream window bounds the
	// throughput of one stream (a protocol multiplexed over a single lane
	// stream shares it), and the connection window bounds the dock's
	// aggregate. Zero uses the defaults of 16 MiB per stream and 64 MiB
	// per connection, which match the edge's defaults. A window bounds only
	// buffered, unread data, so its memory cost is paid per active
	// transfer, not per idle dock.
	MaxStreamReceiveWindow     uint64
	MaxConnectionReceiveWindow uint64

	// MaxIncomingStreams bounds the concurrent bidirectional streams the
	// edge may open toward this dock on QUIC; every inbound lane stream and
	// RPC is one. Zero keeps quic-go's default of 100. A dock that serves
	// many concurrent streams (for example a share behind a gateway)
	// raises it.
	MaxIncomingStreams int64

	// FallbackEndpoint is the TCP+TLS fallback dial target (host:port).
	// Empty uses Endpoint, for an edge that serves both transports on one
	// host:port.
	FallbackEndpoint string
	// FallbackThreshold bounds the QUIC attempt before the fallback is
	// dialed, because blocked UDP usually fails by silence rather than by
	// refusal. Zero means 3 seconds. With a context deadline, the QUIC
	// attempt gets at most half of the remaining time.
	FallbackThreshold time.Duration
	// ForceFallback skips QUIC and dials the fallback directly. It is for
	// diagnostics and tests.
	ForceFallback bool
}

// Dock is one live, admitted dock.
type Dock struct {
	conn      transportConn
	transport string
	control   transportStream

	gen              dc.DockGen
	grantedKeepalive time.Duration

	drained chan struct{}

	// lane holds the lane registry and inbound stream dispatch state,
	// initialized on first use by laneset.
	laneOnce sync.Once
	lane     *laneSet
}

// ErrDrained is returned for operations on a dock the edge asked to
// drain.
var ErrDrained = errors.New("dock: edge requested drain")

// ErrOverloaded is the edge's typed admission refusal: a rate or capacity
// budget shed the dock. Retry after RetryAfter plus your own jitter, or
// dock elsewhere. RetryAfter is advisory, not a reservation, and is zero
// when the edge closed the connection with the overloaded code before
// sending its hint.
type ErrOverloaded struct {
	RetryAfter time.Duration
}

func (e ErrOverloaded) Error() string {
	return fmt.Sprintf("dock: edge overloaded; retry after %s + jitter", e.RetryAfter)
}

// Open dials the edge and completes the explicitly selected control
// handshake: dock/2 when Admission is nil, dock/3 when it is non-nil. A
// dock/3 error never falls back to dock/2. The returned dock carries the
// edge-disclosed generation. ctx bounds connection setup and the control
// handshake; canceling it after a successful return does not close the dock.
func Open(ctx context.Context, cfg Config) (*Dock, error) {
	signerPublic, err := validateDemandAdmission(cfg)
	if err != nil {
		return nil, err
	}
	keepalive := time.Duration(cfg.KeepaliveMs) * time.Millisecond
	if keepalive == 0 {
		keepalive = 20 * time.Second // transport keepalive and idle basis when no cadence is requested
	}
	conn, transport, err := dialTransport(ctx, cfg, keepalive)
	if err != nil {
		return nil, err
	}
	return openDock(ctx, cfg, conn, transport, signerPublic)
}

func openDock(ctx context.Context, cfg Config, conn transportConn, transport string, signerPublic ed25519.PublicKey) (_ *Dock, resultErr error) {
	canceled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(canceled)
		_ = abandonTransport(conn, "opening canceled")
	})
	defer func() {
		if stop != nil && !stop() {
			<-canceled
		}
		if resultErr != nil && ctx.Err() != nil {
			// Closing the transport unblocks I/O with its own error. Preserve
			// both that cause and the caller's cancellation classification.
			resultErr = errors.Join(resultErr, ctx.Err())
		}
	}()

	control, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = abandonTransport(conn, "control open")
		return nil, err
	}
	var predecessor *pb.DockGen
	if cfg.Predecessor != nil {
		predecessor, err = wire.GenToProtoV2(*cfg.Predecessor)
		if err != nil {
			_ = abandonTransport(conn, "predecessor")
			return nil, err
		}
	}
	if err := writeDockOpening(control, conn, cfg, predecessor, signerPublic); err != nil {
		_ = abandonTransport(conn, "hello write")
		return nil, err
	}

	var e2c dockpb.EdgeToClient
	if deadline, ok := ctx.Deadline(); ok {
		_ = control.SetReadDeadline(deadline)
	} else {
		_ = control.SetReadDeadline(time.Now().Add(10 * time.Second))
	}
	if err := wire.ReadFrame(control, &e2c, 0); err != nil {
		_ = abandonTransport(conn, "welcome read")
		// A connection closed with the overloaded code before the typed
		// frame arrived is still a typed refusal, without the hint.
		var appErr *quic.ApplicationError
		if errors.As(err, &appErr) && uint64(appErr.ErrorCode) == wire.DockCodeOverloaded {
			return nil, ErrOverloaded{}
		}
		var connErr *fallback.ConnError
		if errors.As(err, &connErr) && connErr.Code == wire.DockCodeOverloaded {
			return nil, ErrOverloaded{}
		}
		return nil, fmt.Errorf("dock: welcome: %w", err)
	}
	_ = control.SetReadDeadline(time.Time{})
	if over := e2c.GetOverloaded(); over != nil {
		_ = abandonTransport(conn, "overloaded")
		return nil, ErrOverloaded{RetryAfter: time.Duration(over.GetRetryAfterMs()) * time.Millisecond}
	}
	welcome := e2c.GetWelcome()
	if welcome == nil || welcome.GetGen() == nil {
		_ = abandonTransport(conn, "no welcome")
		return nil, errors.New("dock: edge sent no welcome")
	}
	// Disarm opening cancellation before transferring the connection. If the
	// callback already started, wait for it and refuse the canceled connection.
	canceling := !stop()
	stop = nil
	if canceling {
		<-canceled
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		_ = abandonTransport(conn, "opening canceled")
		return nil, err
	}

	d := &Dock{
		conn:             conn,
		transport:        transport,
		control:          control,
		gen:              wire.GenFromProtoV2(welcome.GetGen()),
		grantedKeepalive: time.Duration(welcome.GetKeepaliveMs()) * time.Millisecond,
		drained:          make(chan struct{}),
	}
	go d.watchControl()
	if !cfg.DisableKeepalive {
		go d.keepaliveLoop()
	}
	return d, nil
}

func abandonTransport(conn transportConn, reason string) error {
	if fallback, ok := conn.(*fallbackTransportConn); ok {
		// Graceful fallback close writes a frame behind any blocked write.
		// Close the underlying TCP socket without a TLS close_notify write.
		err := fallback.raw.Close()
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
	return conn.CloseWithError(wire.DockCodeProtocol, reason)
}

// validateDemandAdmission performs every judgment that does not require a
// live connection. It returns the exact Ed25519 public key used to verify the
// locally produced proof. A nil result means the caller selected dock/2.
func validateDemandAdmission(cfg Config) (ed25519.PublicKey, error) {
	if cfg.Admission == nil {
		return nil, nil
	}
	if _, _, err := wire.ParseZoneAdmissionLease(cfg.Admission.LeaseEnvelope, uint64(time.Now().Unix())); err != nil {
		return nil, fmt.Errorf("dock: dock/3 lease: %w", err)
	}
	if cfg.Admission.Signer == nil {
		return nil, errors.New("dock: dock/3 signer is required")
	}
	signerPublic, ok := cfg.Admission.Signer.Public().(ed25519.PublicKey)
	if !ok || len(signerPublic) != ed25519.PublicKeySize {
		return nil, errors.New("dock: dock/3 signer must be Ed25519")
	}
	if len(cfg.SVID.Certificate) == 0 {
		return nil, errors.New("dock: dock/3 SVID leaf is required")
	}
	leaf := cfg.SVID.Leaf
	var err error
	if leaf == nil {
		leaf, err = x509.ParseCertificate(cfg.SVID.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("dock: dock/3 parse SVID leaf: %w", err)
		}
	}
	leafPublic, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(leafPublic, signerPublic) {
		return nil, errors.New("dock: dock/3 signer does not match SVID leaf")
	}
	return append(ed25519.PublicKey(nil), signerPublic...), nil
}

func writeDockOpening(control transportStream, conn transportConn, cfg Config, predecessor *pb.DockGen, signerPublic ed25519.PublicKey) error {
	if cfg.Admission == nil {
		return wire.WriteFrame(control, &dockpb.ClientToEdge{Msg: &dockpb.ClientToEdge_Hello{Hello: &dockpb.DockHello{
			Contract: "dock/2", KeepaliveMs: cfg.KeepaliveMs, PredecessorGen: predecessor,
		}}})
	}
	exporter, err := conn.ExportKeyingMaterial(admissionpb.TLSExporterLabel, []byte{}, admissionpb.TLSExporterBytes)
	if err != nil {
		return fmt.Errorf("dock: dock/3 TLS exporter: %w", err)
	}
	proofInput, err := wire.BuildDockProofInput(cfg.Admission.LeaseEnvelope, cfg.KeepaliveMs, predecessor, exporter)
	if err != nil {
		return fmt.Errorf("dock: dock/3 proof input: %w", err)
	}
	proofSignature, err := cfg.Admission.Signer.Sign(rand.Reader, wire.DockProofSignatureInput(proofInput), crypto.Hash(0))
	if err != nil {
		return fmt.Errorf("dock: dock/3 proof signature: %w", err)
	}
	if err := wire.VerifyDockProof(proofInput, proofSignature, signerPublic, cfg.Admission.LeaseEnvelope, cfg.KeepaliveMs, predecessor, exporter); err != nil {
		return fmt.Errorf("dock: dock/3 generated proof: %w", err)
	}
	hello := &dockv3pb.DockHello{
		Contract: dockv3pb.Contract, KeepaliveMs: cfg.KeepaliveMs, PredecessorGen: predecessor,
		LeaseEnvelope:  append([]byte(nil), cfg.Admission.LeaseEnvelope...),
		DockProofInput: proofInput, DockProofSignature: proofSignature,
	}
	if err := wire.ValidateDockHelloV3(hello); err != nil {
		return fmt.Errorf("dock: dock/3 hello: %w", err)
	}
	opening, err := wire.MarshalCanonical(&dockv3pb.ClientToEdge{Msg: &dockv3pb.ClientToEdge_Hello{Hello: hello}})
	if err != nil {
		return fmt.Errorf("dock: dock/3 canonical hello: %w", err)
	}
	return wire.WriteRawFrame(control, opening)
}

// Keepalive jitter window, as percentages of the granted cadence. The
// ceiling keeps every keepalive early: firing no later than 80% of the
// grant means one lost datagram cannot push the gap past the edge's
// detection window. The floor bounds the extra send rate the jitter
// costs (the mean interval is 72.5% of the grant).
const (
	keepaliveJitterFloorPct = 65
	keepaliveJitterCeilPct  = 80
)

// keepaliveDelay draws the wait before the next keepalive: uniform in
// [65%, 80%] of the granted cadence, independently each interval.
//
// The draw exists because strictly periodic senders sharing a congested
// path phase-align over time: a send delayed by loss recovery re-anchors
// its timer inside the busy window, so alignment accumulates and a large
// dock population turns a smooth aggregate keepalive rate into periodic
// bursts at the cadence period. An independent draw per interval breaks
// that feedback and keeps the aggregate arrival rate flat, which is what
// the edge's receive path is provisioned for.
func keepaliveDelay(granted time.Duration) time.Duration {
	floor := granted * keepaliveJitterFloorPct / 100
	width := granted*keepaliveJitterCeilPct/100 - floor
	return floor + mrand.N(width+1)
}

// keepaliveLoop honors the granted cadence: one small unit of transport
// activity per interval keeps the NAT binding and the edge's idle clock
// alive. It stops when the connection ends or a send fails.
func (d *Dock) keepaliveLoop() {
	granted := d.grantedKeepalive
	if granted <= 0 {
		granted = 15 * time.Second
	}
	t := time.NewTimer(keepaliveDelay(granted))
	defer t.Stop()
	for {
		select {
		case <-d.conn.Context().Done():
			return
		case <-t.C:
			if err := d.conn.SendKeepalive(); err != nil {
				return
			}
			t.Reset(keepaliveDelay(granted))
		}
	}
}

// watchControl consumes edge-to-client control frames: drain requests
// and lane lifecycle (LaneAttached and LaneClosed, which are the only
// source of lane state). Frames are processed in stream order, and each
// lane change is applied to the registry before the next frame is read.
func (d *Dock) watchControl() {
	for {
		var e2c dockpb.EdgeToClient
		if err := wire.ReadFrame(d.control, &e2c, 0); err != nil {
			return
		}
		switch {
		case e2c.GetDrain() != nil:
			select {
			case <-d.drained:
			default:
				close(d.drained)
			}
		case e2c.GetLaneAttached() != nil:
			d.laneAttached(e2c.GetLaneAttached())
		case e2c.GetLaneClosed() != nil:
			d.laneClosed(e2c.GetLaneClosed())
		}
	}
}

// Gen is the generation the edge assigned to this dock. Its nonce is the
// succession credential: keep it in memory, and send it only as
// Config.Predecessor of a later dock, inside that dock's TLS connection.
// Never log or persist it.
func (d *Dock) Gen() dc.DockGen { return d.gen }

// Keepalive is the keepalive cadence the edge granted.
func (d *Dock) Keepalive() time.Duration { return d.grantedKeepalive }

// Resumed reports whether this dock's TLS handshake resumed an earlier
// session from Config.SessionCache. It is for diagnostics; dock semantics
// are identical either way.
func (d *Dock) Resumed() bool { return d.conn.Resumed() }

// Transport names the transport this dock uses: wire.TransportQUIC or
// wire.TransportTCPFallback.
func (d *Dock) Transport() string { return d.transport }

// Drained is closed when the edge asks this dock to drain. The client
// should finish in-flight work, close the dock and redock.
func (d *Dock) Drained() <-chan struct{} { return d.drained }

// Context is canceled when the dock ends.
func (d *Dock) Context() context.Context { return d.conn.Context() }

// Close ends the dock gracefully, closing the connection with
// wire.DockCodeDrain so the edge records a deliberate end.
func (d *Dock) Close() error {
	return d.conn.CloseWithError(wire.DockCodeDrain, "drain")
}

// Abandon ends the dock abruptly without a graceful transport close. On
// QUIC it closes the connection with wire.DockCodeProtocol; on the
// fallback it closes the underlying TCP socket, which also interrupts
// blocked frame writes and stream resets. It ends every stream on this
// dock.
func (d *Dock) Abandon() error {
	return abandonTransport(d.conn, "abandon")
}
