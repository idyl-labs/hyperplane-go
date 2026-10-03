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
	"errors"
	"os"
	"testing"
	"time"
)

// TestReadDeadlineInThePast checks that a deadline already passed fails a
// Read with nothing buffered at once, yet never hides data that is
// already buffered: available bytes are always returned first.
func TestReadDeadlineInThePast(t *testing.T) {
	c, p := newRawPeer(t, Server, 0)
	p.mustSend(t, typeOpenBidi, 1, nil)
	s := acceptOne(t, c)

	if err := s.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline = %v, want nil", err)
	}
	if _, err := s.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read = %v, want os.ErrDeadlineExceeded", err)
	}

	p.mustSend(t, typeData, 1, []byte("ok"))
	p.sync(t)
	buf := make([]byte, 8)
	if n, err := s.Read(buf); err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("Read past the deadline with data buffered = %q, %v; want \"ok\"", buf[:n], err)
	}
	if _, err := s.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read after draining = %v, want os.ErrDeadlineExceeded", err)
	}
	// A deadline error does not end the stream: clearing the deadline and
	// delivering data makes reads succeed again.
	if err := s.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	p.mustSend(t, typeData, 1, []byte("again"))
	if n, err := s.Read(buf); err != nil || string(buf[:n]) != "again" {
		t.Fatalf("Read after clearing the deadline = %q, %v", buf[:n], err)
	}
	requireOpen(t, c)
}

// TestSetReadDeadlineWakesBlockedRead checks that moving the deadline into
// the past from another goroutine wakes a Read that is already blocked, so
// a caller can always interrupt a reader.
func TestSetReadDeadlineWakesBlockedRead(t *testing.T) {
	c, p := newRawPeer(t, Server, 0)
	p.mustSend(t, typeOpenBidi, 1, nil)
	s := acceptOne(t, c)

	got := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		_, err := s.Read(make([]byte, 1))
		got <- err
	}()
	<-started
	// Replacing an armed deadline stops its timer and arms the new one.
	_ = s.SetReadDeadline(time.Now().Add(time.Hour))
	_ = s.SetReadDeadline(time.Now().Add(-time.Millisecond))
	select {
	case err := <-got:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read = %v, want os.ErrDeadlineExceeded", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked Read was not woken by the deadline")
	}
}
