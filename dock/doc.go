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

// Package dock is the endpoint client for Hyperplane, IDYL's
// authenticated connection fabric. A client opens a dock (one
// authenticated connection to a fabric edge), and then receives the
// traffic the edge routes to it: lanes and their streams, pushed events,
// and inbound RPCs. It can also reach another dock it holds a locator for:
// send it an event, open an RPC to it, or open a lane with it. The package
// implements the wire protocol only; it holds no routing or authorization
// policy of its own.
//
// # Opening a dock
//
// Open dials the edge described by a Config and completes the control
// handshake. It returns an admitted *Dock or an error; it never returns a
// half-open dock. The dock exposes:
//
//	Gen        the generation the edge assigned to this dock
//	Keepalive  the keepalive cadence the edge granted
//	Transport  the transport the dock uses (wire.TransportQUIC or
//	           wire.TransportTCPFallback)
//	Resumed    whether the TLS handshake resumed an earlier session
//	Drained    a channel closed when the edge asks the dock to drain
//	Context    a context canceled when the dock ends
//	Close      ends the dock gracefully with the drain code
//	Abandon    ends the dock abruptly, without a graceful close
//
// The context passed to Open bounds connection setup and the handshake
// only. Canceling it after Open returns does not affect the dock.
//
// # Identity and admission
//
// The client authenticates with its X.509 SVID (Config.SVID) as the TLS
// client certificate; the edge derives the client's identity from that
// certificate alone. The client authenticates the edge by its exact
// SPIFFE ID (Config.ServerID) against the trust bundles in
// Config.Bundles. TLS 1.3 is the minimum version.
//
// The client speaks one of two hello forms on the dock's control stream,
// selected by Config.Admission:
//
//   - dock/2, when Admission is nil: the hello carries no admission
//     material, only the requested keepalive cadence and the optional
//     predecessor generation.
//   - dock/3, when Admission is a *DemandAdmission (demand admission):
//     the hello also carries a signed admission lease, passed through
//     byte for byte, and a proof signed with the SVID's Ed25519 key over
//     a digest of the lease, the hello's keepalive and predecessor fields
//     and this connection's TLS exporter. The
//     proof binds the lease to this one connection, so it cannot be
//     replayed on another. Open validates the lease and the signer before
//     dialing and verifies its own proof before sending the hello. A
//     fresh proof is signed for every connection, including resumed ones.
//
// The two forms are independent. A dock/3 attempt that fails, locally or
// at the edge, returns an error; it is never retried as dock/2.
//
// # Receiving traffic
//
// The edge opens streams toward the dock; the dock accepts them:
//
//	AcceptLane    the next lane the edge attached to this dock
//	AcceptRPC     the next inbound RPC: the opener's metadata and a
//	              bidirectional byte pipe (*RPC)
//	AcceptEvent   the next pushed event payload
//
// A lane is an association between two docks, established by the fabric
// and announced to both of them on their control streams. Each lane
// carries any number of independent bidirectional streams (*LaneStream).
// Either side may open one with Lane.OpenStream; streams the peer opens
// arrive through Lane.AcceptStream. Every lane stream begins with a short
// attribution header (the lane's id, a declared stream class and opaque
// application bytes), and after it is a transparent byte pipe. A lane
// ends exactly once; Lane.Closed then fires and Lane.CloseCause reports
// why. An ended lane never comes back.
//
// A lane granted wire.LaneClassFlow also carries flows: best-effort
// datagrams sent with Lane.SendFlow and received with Lane.ReceiveFlow,
// each tagged with a flow id the sender chooses. Flows need QUIC. Each
// lane queues at most 64 received items and drops the oldest when full,
// and nothing reports a lost datagram, so an application that needs
// delivery uses lane streams.
//
// Inbound RPC streams and lane streams share the dock's connection. The
// client reads the first byte of each inbound stream to tell them apart,
// so all three Accept methods can be used on one dock at the same time.
// NewRPCConn adapts an *RPC to net.Conn for protocols that need one, and
// ReportRPCMetadata is the well-known metadata of a report RPC.
//
// A minimal lane server:
//
//	for {
//		lane, err := d.AcceptLane(ctx)
//		if err != nil {
//			return err // the dock ended or ctx was canceled
//		}
//		go func() {
//			for {
//				s, err := lane.AcceptStream(ctx)
//				if err != nil {
//					return // ErrLaneClosed once the lane has ended
//				}
//				go serve(s) // read to EOF, then s.Close()
//			}
//		}()
//	}
//
// # Reaching other docks
//
// A dock reaches another dock by a locator: a sealed route the fabric
// issues, opaque to the client. Each of these verbs opens its own stream,
// and the edge authorizes the verb before routing it. SendEvent and
// OpenLane finish their stream once the edge has replied; a successful
// OpenRPC keeps its stream as the RPC's byte pipe:
//
//	SendEvent  one payload, best-effort; the target receives it from
//	           AcceptEvent
//	OpenRPC    a bidirectional byte pipe (*RPC); the target receives it
//	           from AcceptRPC
//	OpenLane   a lane with one or two target docks, with the requested
//	           lane classes; each target receives it from AcceptLane
//
// The edge refuses a verb with a typed NakError. A lane's targets can be
// pinned to an expected generation, principal and endpoint kind
// (LaneTarget); the fabric ends the lane as soon as a pinned value no
// longer matches.
//
// # Transports
//
// QUIC is the primary transport. Some networks block UDP, and blocked UDP
// usually fails by silence rather than by refusal, so Open gives the QUIC
// attempt a bounded window (Config.FallbackThreshold, 3 seconds by
// default, and never more than half of the remaining context deadline).
// If QUIC cannot establish a connection in that window, Open dials the
// TCP+TLS fallback transport (package wire/fallback) at
// Config.FallbackEndpoint, or at Config.Endpoint when that is empty.
// Config.ForceFallback skips QUIC entirely.
//
// Only a failure to connect triggers the fallback. A refusal from the
// edge, such as ErrOverloaded, is an answer and is returned as is. The
// fallback carries every stream shape a dock uses, but it has fewer
// properties than QUIC: no datagrams (so no lane flows), no connection
// migration, and head-of-line blocking across streams. Dock.Transport
// reports which transport a dock uses.
//
// # Building stream protocols
//
// Three building blocks serve a stream protocol that this package does
// not implement itself, run on a dock's connection:
//
//	Dock.OpenStream  a new bidirectional Stream on the connection, with
//	                 nothing written; its first byte selects the protocol
//	                 at the edge
//	Dock.WaitLane    the lane with a given id, once its LaneAttached
//	                 arrives, for a protocol whose reply names a lane
//	NewRPC           an *RPC over a Stream, for a protocol that
//	                 establishes an RPC
//	FinishStream     the clean end of a one-shot exchange: FIN, then the
//	                 peer's data read to EOF, with a bounded wait
//
// Lanes, RPCs and events, as described above, need none of them.
//
// # Session resumption
//
// Set Config.SessionCache to a tls.ClientSessionCache shared across a
// client's docks (for example tls.NewLRUClientSessionCache) to resume TLS
// sessions. A resumed handshake skips the certificate exchange, which
// makes reconnecting cheaper. Resumption does not change dock semantics;
// Dock.Resumed reports it for diagnostics.
//
// # Recipe: the redock loop
//
// A dock ends for many reasons: the edge asks it to drain, the edge
// restarts, or the network changes. The response is always the same:
// open a new dock and name the previous generation in
// Config.Predecessor. That declaration makes the new dock a succession:
// the fabric treats it as the same client continuing on a new
// generation, so the client stays addressable while the previous
// generation drains.
//
//	cache := tls.NewLRUClientSessionCache(4)
//	var pred *generation.DockGen // nil for the first dock
//	backoff := time.Second
//	for {
//		d, err := dock.Open(ctx, dock.Config{
//			Endpoint: endpoint, ServerID: serverID,
//			SVID: svid, Bundles: bundles,
//			Admission: &dock.DemandAdmission{
//				LeaseEnvelope: lease, Signer: signer,
//			},
//			Predecessor: pred, SessionCache: cache,
//		})
//		var over dock.ErrOverloaded
//		switch {
//		case errors.As(err, &over):
//			// The edge shed this attempt: wait at least the hint, plus jitter.
//			sleep(over.RetryAfter + jitter(backoff))
//			backoff = min(2*backoff, maxBackoff)
//			continue
//		case err != nil:
//			sleep(jitter(backoff)) // jittered exponential backoff
//			backoff = min(2*backoff, maxBackoff)
//			continue
//		}
//		backoff = time.Second
//		gen := d.Gen() // holds the succession credential: never log it
//		pred = &gen
//
//		// Serve until the edge asks to drain or the dock ends.
//		select {
//		case <-d.Drained():
//			_ = d.Close() // finish in-flight work first, then redock
//		case <-d.Context().Done():
//			// The connection ended: redock as a succession.
//		}
//	}
//
// Keep the generation in memory and use it only as a predecessor
// declaration. Its nonce is the succession credential, which lets the next
// dock present itself as this dock's successor. It must never be written
// to logs, disk or any other channel.
//
// # Keepalives
//
// After the handshake the dock sends a small keepalive datagram (a PING
// frame on the fallback) at a jittered interval below the granted
// cadence, which keeps NAT bindings and the edge's idle timer alive.
// Config.KeepaliveMs requests a cadence; zero lets the edge choose.
//
// Config.DisableKeepalive turns off all keepalive traffic from the
// client, so a dock that goes silent is detected only by the edge's idle
// timeout. It exists for tests and diagnostics that exercise that
// detection path; ordinary clients leave it unset.
package dock
