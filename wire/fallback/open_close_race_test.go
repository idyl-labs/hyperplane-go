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

package fallback

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestPeerOpenRacingCloseNeverStrandsAStream checks that a stream the peer
// opens while the connection is failing is never handed out alive: either
// Accept fails, or the accepted stream's context is done and its Read
// returns ErrConnClosed. A stream registered after the connection failed
// would never be terminated, and its Read would block forever.
//
// The window is the instant between the read loop consuming an OPEN header
// and registering the stream, so the test calls fail (what CloseWithError
// and every transport error end in) right after the OPEN is consumed, many
// times over.
func TestPeerOpenRacingCloseNeverStrandsAStream(t *testing.T) {
	stranded := 0
	for range 3000 {
		c, p := newRawPeer(t, Server, 0)
		// The write returns once the read loop has consumed the frame, so
		// fail below races the read loop's handling of it.
		p.mustSend(t, typeOpenBidi, 1, nil)
		c.fail(&ConnError{Code: 0x10, Reason: "closing"})

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		s, err := c.AcceptStream(ctx)
		cancel()
		if err != nil {
			continue // the open lost the race to the close: nothing to strand
		}
		select {
		case <-s.Context().Done():
		case <-time.After(time.Second):
			stranded++
			continue
		}
		if _, err := s.Read(make([]byte, 1)); !errors.Is(err, ErrConnClosed) {
			t.Fatalf("Read on a stream accepted after close = %v, want ErrConnClosed", err)
		}
	}
	if stranded > 0 {
		t.Fatalf("%d streams accepted after their connection failed are still live", stranded)
	}
}
