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
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/idyl-labs/hyperplane-go/wire"
	mpb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
	dockpb "github.com/idyl-labs/hyperplane-go/wire/dockv3"
)

// frameTestGen is a small, fully populated message used as frame content.
func frameTestGen() *mpb.DockGen {
	return &mpb.DockGen{
		Edge:      &mpb.EdgeTag{Incarnation: []byte("edge-a"), LeaseId: []byte("lease-a")},
		Slot:      7,
		SlotEpoch: 9,
		Nonce:     []byte("nonce-000001"),
	}
}

// framePrefix returns the 4-byte big-endian length prefix for n bytes.
func framePrefix(n uint32) []byte {
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], n)
	return prefix[:]
}

// failingWriter accepts a fixed number of Write calls and then fails, so a
// test can fail the prefix write or the body write separately.
type failingWriter struct {
	accept int
	err    error
	buf    bytes.Buffer
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.accept == 0 {
		return 0, w.err
	}
	w.accept--
	return w.buf.Write(p)
}

// TestFrameRoundTripPreservesMessage checks that a frame written by
// WriteFrame is a 4-byte big-endian length followed by exactly the marshaled
// message, and that ReadFrame decodes it back to an equal message. Both
// peers of a control stream depend on this exact layout.
func TestFrameRoundTripPreservesMessage(t *testing.T) {
	var buf bytes.Buffer
	sent := frameTestGen()
	if err := wire.WriteFrame(&buf, sent); err != nil {
		t.Fatal(err)
	}
	body, err := proto.Marshal(sent)
	if err != nil {
		t.Fatal(err)
	}
	want := append(framePrefix(uint32(len(body))), body...)
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("frame bytes = %x, want %x", buf.Bytes(), want)
	}
	if buf.Bytes()[0] != 0x00 {
		t.Fatal("a frame under the default cap must begin with 0x00")
	}

	var got mpb.DockGen
	if err := wire.ReadFrame(&buf, &got, 0); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(&got, sent) {
		t.Fatalf("decoded %v, want %v", &got, sent)
	}
	if buf.Len() != 0 {
		t.Fatalf("ReadFrame left %d bytes unread", buf.Len())
	}
}

// TestFrameReadsConsecutiveFramesExactly checks that ReadRawFrame consumes
// exactly one frame, so several frames on one stream decode in order and
// the bytes after a frame stay with the caller.
func TestFrameReadsConsecutiveFramesExactly(t *testing.T) {
	var buf bytes.Buffer
	frames := [][]byte{{}, []byte("a"), bytes.Repeat([]byte{0xee}, 300)}
	for _, frame := range frames {
		if err := wire.WriteRawFrame(&buf, frame); err != nil {
			t.Fatal(err)
		}
	}
	buf.WriteString("tail")
	for i, want := range frames {
		got, err := wire.ReadRawFrame(&buf, 0)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("frame %d = %x, want %x", i, got, want)
		}
	}
	if buf.String() != "tail" {
		t.Fatalf("bytes after the frames = %q, want %q", buf.String(), "tail")
	}
}

// TestWriteRawFrameCapBoundary checks the sender's cap: a frame of exactly
// DefaultMaxFrame bytes is written, one byte more is refused with
// ErrFrameTooLarge before anything reaches the writer, so a peer never sees
// a partial oversized frame.
func TestWriteRawFrameCapBoundary(t *testing.T) {
	var buf bytes.Buffer
	if err := wire.WriteRawFrame(&buf, make([]byte, wire.DefaultMaxFrame)); err != nil {
		t.Fatalf("frame at the cap refused: %v", err)
	}
	if buf.Len() != 4+wire.DefaultMaxFrame {
		t.Fatalf("wrote %d bytes, want %d", buf.Len(), 4+wire.DefaultMaxFrame)
	}

	buf.Reset()
	err := wire.WriteRawFrame(&buf, make([]byte, wire.DefaultMaxFrame+1))
	if !errors.Is(err, wire.ErrFrameTooLarge) {
		t.Fatalf("frame one over the cap: err = %v, want ErrFrameTooLarge", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("refused frame wrote %d bytes", buf.Len())
	}
}

// TestWriteFrameRefusesOversizedMessage checks that a message whose
// encoding exceeds DefaultMaxFrame is refused with ErrFrameTooLarge and
// writes nothing.
func TestWriteFrameRefusesOversizedMessage(t *testing.T) {
	var buf bytes.Buffer
	oversized := &mpb.DockGen{Nonce: make([]byte, wire.DefaultMaxFrame)}
	if err := wire.WriteFrame(&buf, oversized); !errors.Is(err, wire.ErrFrameTooLarge) {
		t.Fatalf("err = %v, want ErrFrameTooLarge", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("refused message wrote %d bytes", buf.Len())
	}
}

// TestWriteFrameReportsMarshalFailure checks that a message that cannot be
// marshaled (a string field holding invalid UTF-8) is reported as an error
// and nothing is written.
func TestWriteFrameReportsMarshalFailure(t *testing.T) {
	var buf bytes.Buffer
	if err := wire.WriteFrame(&buf, &dockpb.DockHello{Contract: "\xff"}); err == nil {
		t.Fatal("unmarshalable message was framed")
	}
	if buf.Len() != 0 {
		t.Fatalf("failed marshal wrote %d bytes", buf.Len())
	}
}

// TestFrameWritersPropagateWriterErrors checks that a failure on the prefix
// write or on the body write is returned unchanged, so the caller can tell a
// broken stream from a refused frame.
func TestFrameWritersPropagateWriterErrors(t *testing.T) {
	broken := errors.New("stream broken")
	writers := map[string]func(io.Writer) error{
		"WriteFrame":    func(w io.Writer) error { return wire.WriteFrame(w, frameTestGen()) },
		"WriteRawFrame": func(w io.Writer) error { return wire.WriteRawFrame(w, []byte("body")) },
	}
	for name, write := range writers {
		for accept := 0; accept < 2; accept++ {
			w := &failingWriter{accept: accept, err: broken}
			if err := write(w); !errors.Is(err, broken) {
				t.Errorf("%s with %d accepted writes: err = %v, want the writer error", name, accept, err)
			}
		}
	}
}

// TestReadRawFrameCapBoundary checks the receiver's cap: a declared length
// equal to the cap is read, one byte more is refused with ErrFrameTooLarge
// before the body is read, so a peer cannot make the receiver buffer more
// than it agreed to.
func TestReadRawFrameCapBoundary(t *testing.T) {
	const capBytes = 64
	body := bytes.Repeat([]byte{0x5a}, capBytes)
	got, err := wire.ReadRawFrame(bytes.NewReader(append(framePrefix(capBytes), body...)), capBytes)
	if err != nil {
		t.Fatalf("frame at the cap refused: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatal("frame at the cap returned different bytes")
	}

	over := append(framePrefix(capBytes+1), bytes.Repeat([]byte{0x5a}, capBytes+1)...)
	r := bytes.NewReader(over)
	if _, err := wire.ReadRawFrame(r, capBytes); !errors.Is(err, wire.ErrFrameTooLarge) {
		t.Fatalf("frame one over the cap: err = %v, want ErrFrameTooLarge", err)
	}
	if r.Len() != capBytes+1 {
		t.Fatalf("refusal consumed %d body bytes, want none", capBytes+1-r.Len())
	}
}

// TestReadRawFrameNonPositiveCapMeansDefault checks that maxLen <= 0 applies
// DefaultMaxFrame rather than no cap: a declared length at the default is
// read and one more is refused.
func TestReadRawFrameNonPositiveCapMeansDefault(t *testing.T) {
	atCap := append(framePrefix(wire.DefaultMaxFrame), make([]byte, wire.DefaultMaxFrame)...)
	for _, maxLen := range []int{0, -1} {
		got, err := wire.ReadRawFrame(bytes.NewReader(atCap), maxLen)
		if err != nil {
			t.Fatalf("maxLen %d: frame at the default cap refused: %v", maxLen, err)
		}
		if len(got) != wire.DefaultMaxFrame {
			t.Fatalf("maxLen %d: read %d bytes, want %d", maxLen, len(got), wire.DefaultMaxFrame)
		}
		over := framePrefix(wire.DefaultMaxFrame + 1)
		if _, err := wire.ReadRawFrame(bytes.NewReader(over), maxLen); !errors.Is(err, wire.ErrFrameTooLarge) {
			t.Fatalf("maxLen %d: err = %v, want ErrFrameTooLarge", maxLen, err)
		}
	}
	huge := framePrefix(0xffffffff)
	if _, err := wire.ReadRawFrame(bytes.NewReader(huge), 0); !errors.Is(err, wire.ErrFrameTooLarge) {
		t.Fatalf("maximum declared length: err = %v, want ErrFrameTooLarge", err)
	}
}

// TestReadRawFrameTruncation checks how an ended stream is reported: never
// as a short frame. The errors are those of io.ReadFull on the prefix and
// then on the body: an end before any byte of either is io.EOF, and an end
// partway through either is io.ErrUnexpectedEOF.
func TestReadRawFrameTruncation(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
		want  error
	}{
		{"empty stream", nil, io.EOF},
		{"partial prefix", []byte{0x00, 0x00}, io.ErrUnexpectedEOF},
		{"prefix only", framePrefix(3), io.EOF},
		{"short body", append(framePrefix(3), 'a', 'b'), io.ErrUnexpectedEOF},
	}
	for _, tc := range cases {
		got, err := wire.ReadRawFrame(bytes.NewReader(tc.input), 0)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
		if got != nil {
			t.Errorf("%s: returned %d bytes with an error", tc.name, len(got))
		}
	}
}

// TestReadFrameReportsUndecodableBody checks that a frame within the cap
// whose body is not a valid encoding of the target message is an error,
// distinct from the size refusal.
func TestReadFrameReportsUndecodableBody(t *testing.T) {
	body := []byte{0x0a, 0x05, 'a'} // field 1, declared 5 bytes, 1 present
	var got mpb.DockGen
	err := wire.ReadFrame(bytes.NewReader(append(framePrefix(uint32(len(body))), body...)), &got, 0)
	if err == nil {
		t.Fatal("undecodable body accepted")
	}
	if errors.Is(err, wire.ErrFrameTooLarge) {
		t.Fatalf("undecodable body reported as oversized: %v", err)
	}

	err = wire.ReadFrame(bytes.NewReader(framePrefix(17)), &got, 16)
	if !errors.Is(err, wire.ErrFrameTooLarge) {
		t.Fatalf("ReadFrame over its cap: err = %v, want ErrFrameTooLarge", err)
	}
}
