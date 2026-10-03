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

package dock_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/idyl-labs/hyperplane-go/dock"
	"github.com/idyl-labs/hyperplane-go/generation"
	"github.com/idyl-labs/hyperplane-go/wire"
)

// The client's credentials. A real client obtains its X.509 SVID, the
// SVID's Ed25519 key and the trust bundles from its SPIFFE Workload API,
// and its signed admission lease from its lease issuer.
var (
	edgeEndpoint = "edge.example.com:443"
	edgeID       = spiffeid.RequireFromString("spiffe://example.com/fabric/edge")
	svid         tls.Certificate
	svidKey      ed25519.PrivateKey
	bundles      x509bundle.Source
	lease        []byte
)

// Open a dock with demand admission (the dock/3 hello) and serve the lanes
// the edge attaches to it. Each lane carries independent streams; this
// server echoes every stream back to its opener.
func ExampleOpen() {
	ctx := context.Background()
	d, err := dock.Open(ctx, dock.Config{
		Endpoint: edgeEndpoint,
		ServerID: edgeID,
		SVID:     svid,
		Bundles:  bundles,
		Admission: &dock.DemandAdmission{
			LeaseEnvelope: lease,
			Signer:        svidKey,
		},
	})
	if err != nil {
		fmt.Println("open:", err)
		return
	}
	defer func() { _ = d.Close() }()

	for {
		lane, err := d.AcceptLane(ctx)
		if err != nil {
			return // the dock ended or ctx was canceled
		}
		go func() {
			for {
				s, err := lane.AcceptStream(ctx)
				if err != nil {
					return // ErrLaneClosed once the lane has ended
				}
				go echo(s)
			}
		}()
	}
}

// echo copies a lane stream back to its opener until the opener's EOF,
// then closes the write side, which finishes the stream cleanly.
func echo(s *dock.LaneStream) {
	if _, err := io.Copy(s, s); err != nil {
		s.Abort()
		return
	}
	_ = s.Close()
}

// The redock loop. Every dock ends eventually; the client opens the next
// one with the previous generation as its predecessor, so the fabric
// treats it as the same client continuing. An overloaded edge's retry hint
// is honored, and every retry is jittered.
func Example_redockLoop() {
	ctx := context.Background()
	cache := tls.NewLRUClientSessionCache(4)
	var pred *generation.DockGen // nil for the first dock
	const maxBackoff = time.Minute
	backoff := time.Second
	for ctx.Err() == nil {
		d, err := dock.Open(ctx, dock.Config{
			Endpoint: edgeEndpoint, ServerID: edgeID,
			SVID: svid, Bundles: bundles,
			Admission: &dock.DemandAdmission{
				LeaseEnvelope: lease, Signer: svidKey,
			},
			Predecessor: pred, SessionCache: cache,
		})
		var over dock.ErrOverloaded
		switch {
		case errors.As(err, &over):
			// The edge shed this attempt: wait at least the hint, plus jitter.
			sleep(ctx, over.RetryAfter+jitter(backoff))
			backoff = min(2*backoff, maxBackoff)
			continue
		case err != nil:
			sleep(ctx, jitter(backoff))
			backoff = min(2*backoff, maxBackoff)
			continue
		}
		backoff = time.Second
		gen := d.Gen() // holds the succession credential: never log it
		pred = &gen

		// Serve until the edge asks to drain or the dock ends.
		select {
		case <-d.Drained():
			_ = d.Close() // finish in-flight work first, then redock
		case <-d.Context().Done():
			// The connection ended: redock as a succession.
		}
	}
}

// jitter draws a wait uniformly from [d/2, d].
func jitter(d time.Duration) time.Duration { return d/2 + rand.N(d/2+1) }

// sleep waits for d or until ctx ends.
func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// Serve report RPCs: a peer that wants this dock to report opens an RPC
// carrying ReportRPCMetadata, and the dock runs its own session protocol
// over the RPC through NewRPCConn.
func ExampleDock_AcceptRPC() {
	ctx := context.Background()
	d, err := dock.Open(ctx, dock.Config{
		Endpoint: edgeEndpoint, ServerID: edgeID,
		SVID: svid, Bundles: bundles,
	})
	if err != nil {
		fmt.Println("open:", err)
		return
	}
	defer func() { _ = d.Close() }()

	for {
		metadata, rpc, err := d.AcceptRPC(ctx)
		if err != nil {
			return // the dock ended or ctx was canceled
		}
		if string(metadata) != dock.ReportRPCMetadata {
			rpc.Abort() // not a protocol this dock serves
			continue
		}
		go func() {
			conn := dock.NewRPCConn(rpc, nil) // the dock outlives the RPC
			defer func() { _ = conn.Close() }()
			_, _ = io.Copy(conn, conn) // a real report session runs here
		}()
	}
}

// Echo the flows on every lane granted the flow class. Flows are
// best-effort datagrams: an item may be lost, and the echo is a new send
// that may be lost too.
func ExampleLane_ReceiveFlow() {
	ctx := context.Background()
	d, err := dock.Open(ctx, dock.Config{
		Endpoint: edgeEndpoint, ServerID: edgeID,
		SVID: svid, Bundles: bundles,
		Admission: &dock.DemandAdmission{
			LeaseEnvelope: lease, Signer: svidKey,
		},
	})
	if err != nil {
		fmt.Println("open:", err)
		return
	}
	defer func() { _ = d.Close() }()

	for {
		lane, err := d.AcceptLane(ctx)
		if err != nil {
			return // the dock ended or ctx was canceled
		}
		if lane.Classes()&wire.LaneClassFlow == 0 {
			continue // this lane carries streams only
		}
		go func() {
			for {
				flowID, payload, err := lane.ReceiveFlow(ctx)
				if err != nil {
					return // ErrLaneClosed once the lane has ended
				}
				_ = lane.SendFlow(flowID, payload) // best-effort, like the item it answers
			}
		}()
	}
}

// An overloaded edge refuses a dock with ErrOverloaded; its RetryAfter is
// the edge's advisory hint, to which the client adds its own jitter.
func ExampleErrOverloaded() {
	// Open returns errors like this one when the edge sheds the attempt.
	err := fmt.Errorf("redock: %w", dock.ErrOverloaded{RetryAfter: 1500 * time.Millisecond})

	var over dock.ErrOverloaded
	if errors.As(err, &over) {
		fmt.Println("retry after", over.RetryAfter)
	}
	fmt.Println(err)
	// Output:
	// retry after 1.5s
	// redock: dock: edge overloaded; retry after 1.5s + jitter
}

// loopbackRPC is an in-memory RPCStream: what is written is read back.
type loopbackRPC struct{ bytes.Buffer }

func (*loopbackRPC) Close() error { return nil }
func (*loopbackRPC) Abort()       { fmt.Println("rpc aborted") }

// NewRPCConn adapts an RPC to net.Conn. Closing the connection aborts the
// RPC and then runs onClose, exactly once.
func ExampleNewRPCConn() {
	rpc := &loopbackRPC{} // in a client, the *dock.RPC from AcceptRPC
	conn := dock.NewRPCConn(rpc, func() error {
		fmt.Println("dock closed")
		return nil
	})

	_, _ = io.WriteString(conn, "status")
	reply := make([]byte, len("status"))
	_, _ = io.ReadFull(conn, reply)
	fmt.Println(string(reply), conn.RemoteAddr())

	_ = conn.Close()
	_ = conn.Close() // a second Close does nothing more
	// Output:
	// status hyperplane-rpc
	// rpc aborted
	// dock closed
}
