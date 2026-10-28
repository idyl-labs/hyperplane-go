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

package datadock

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var testHost = [16]byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x41, 0x11, 0x81, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}

// goldens reads testdata/golden.txt: name, a tab, then lowercase hex. The
// same file pins every other implementation of this contract.
func goldens(tb testing.TB) map[string][]byte {
	tb.Helper()
	file, err := os.Open(filepath.Join("testdata", "golden.txt"))
	if err != nil {
		tb.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	out := make(map[string][]byte)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		name, encoded, ok := strings.Cut(scanner.Text(), "\t")
		if !ok {
			tb.Fatalf("golden line %q is not name<TAB>hex", scanner.Text())
		}
		raw, err := hex.DecodeString(encoded)
		if err != nil {
			tb.Fatalf("golden %s: %v", name, err)
		}
		out[name] = raw
	}
	if err := scanner.Err(); err != nil {
		tb.Fatal(err)
	}
	return out
}

// TestHeaderAndRepliesMatchGoldens pins the header's and every reply's
// bytes, and each golden decodes back to its value.
func TestHeaderAndRepliesMatchGoldens(t *testing.T) {
	golden := goldens(t)
	header := Header{Host: testHost, Sequence: 12, Epoch: 3}
	encoded, err := header.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, golden["header"]) {
		t.Fatalf("header encodes to %x, want %x", encoded, golden["header"])
	}
	if decoded, err := DecodeHeader(golden["header"]); err != nil || decoded != header {
		t.Fatalf("header golden decodes to %+v, %v", decoded, err)
	}
	for code, name := range map[Code]string{
		CodeLinked: "reply-linked", CodeMalformed: "reply-malformed", CodeNotHere: "reply-not-here",
		CodeStaleEpoch: "reply-stale-epoch", CodeEndpointUnavailable: "reply-endpoint-unavailable",
		CodeAtCapacity: "reply-at-capacity", CodeNodeUnavailable: "reply-node-unavailable",
	} {
		reply, err := NewReply(code)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := reply.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, golden[name]) {
			t.Fatalf("%s encodes to %x, want %x", name, encoded, golden[name])
		}
		decoded, err := ReadReply(bytes.NewReader(golden[name]))
		if err != nil || decoded != reply {
			t.Fatalf("%s decodes to %+v, %v", name, decoded, err)
		}
	}
}

// TestDecodeHeaderRefusesAnyOtherForm: another length, another version, a
// nil host and out-of-range values are refused, never read past.
func TestDecodeHeaderRefusesAnyOtherForm(t *testing.T) {
	good, err := Header{Host: testHost, Sequence: 12, Epoch: 3}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(f func([]byte) []byte) []byte { return f(append([]byte(nil), good...)) }
	for name, raw := range map[string][]byte{
		"short":         good[:HeaderBytes-1],
		"long":          append(append([]byte(nil), good...), 0),
		"version 2":     mutate(func(b []byte) []byte { b[0] = 2; return b }),
		"nil host":      mutate(func(b []byte) []byte { copy(b[1:17], make([]byte, 16)); return b }),
		"sequence zero": mutate(func(b []byte) []byte { copy(b[17:25], make([]byte, 8)); return b }),
		"sequence 2^53": mutate(func(b []byte) []byte { copy(b[17:25], []byte{0, 0x20, 0, 0, 0, 0, 0, 0}); return b }),
		"epoch zero":    mutate(func(b []byte) []byte { copy(b[25:33], make([]byte, 8)); return b }),
		"epoch 2^63":    mutate(func(b []byte) []byte { copy(b[25:33], []byte{0x80, 0, 0, 0, 0, 0, 0, 0}); return b }),
	} {
		if _, err := DecodeHeader(raw); !errors.Is(err, ErrMalformed) {
			t.Fatalf("%s: error = %v, want ErrMalformed", name, err)
		}
	}
}

// TestReadReplyReadsOneReplyAndRefusesBadReasons: the reader consumes the
// reply and nothing after it, takes an unknown code as a refusal, and
// refuses a reason outside the grammar.
func TestReadReplyReadsOneReplyAndRefusesBadReasons(t *testing.T) {
	stream := bytes.NewReader([]byte{0, 0, 0x16, 0x03})
	if reply, err := ReadReply(stream); err != nil || !reply.Linked() {
		t.Fatalf("linked reply = %+v, %v", reply, err)
	}
	if rest := stream.Len(); rest != 2 {
		t.Fatalf("the reader consumed past the reply: %d bytes left, want 2", rest)
	}
	if reply, err := ReadReply(bytes.NewReader([]byte{200, 3, 'n', 'e', 'w'})); err != nil || reply.Linked() || reply.Reason != "new" {
		t.Fatalf("unknown code reply = %+v, %v", reply, err)
	}
	for name, raw := range map[string][]byte{
		"linked with reason": {0, 1, 'x'},
		"refusal no reason":  {2, 0},
		"upper case":         {2, 3, 'B', 'a', 'd'},
		"truncated":          {2, 8, 'n', 'o'},
	} {
		if _, err := ReadReply(bytes.NewReader(raw)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestPrincipalIsTheExactDataDockShape(t *testing.T) {
	got, err := Principal("zone-a.zone.example", "Q2xpZW50Tm9kZUlEMDE")
	if err != nil || got != "spiffe://zone-a.zone.example/node/Q2xpZW50Tm9kZUlEMDE/data-dock" {
		t.Fatalf("Principal = %q, %v", got, err)
	}
	for _, tc := range []struct{ td, node string }{
		{"network.example", "n1"},
		{"zone-a.zone.example", ""},
		{"zone-a.zone.example", "a/b"},
		{"Zone-A.zone.example", "n1"},
	} {
		if _, err := Principal(tc.td, tc.node); !errors.Is(err, ErrMalformed) {
			t.Fatalf("Principal(%q, %q) = %v, want ErrMalformed", tc.td, tc.node, err)
		}
	}
}
