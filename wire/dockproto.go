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

package wire

// dockproto.go: dock-protocol constants shared by the edge and the client.

// QUIC application error codes for dock connections. Both the edge and the
// client use them to close a dock connection or to cancel an individual
// stream. Verb-level refusals are carried in protocol messages; these codes
// are the connection- and stream-level outcomes. A code's meaning is fixed
// and never reused.
const (
	// DockCodeDrain is a deliberate, graceful end: the client redocks or
	// has finished.
	DockCodeDrain = 0x10
	// DockCodeBadCert reports that SVID validation failed.
	DockCodeBadCert = 0x01
	// DockCodeOverloaded reports that the edge's admission budget refused
	// the dock; the client may retry later.
	DockCodeOverloaded = 0x02
	// DockCodeProtocol reports that the peer violated the dock protocol.
	DockCodeProtocol = 0x03
)
