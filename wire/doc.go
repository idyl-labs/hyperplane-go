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

// Package wire holds the byte-level encodings a Hyperplane endpoint speaks,
// and the verification of the records it presents when it docks.
//
// It contains:
//
//   - length-prefixed framing for protobuf messages on a stream, with a
//     receiver-side size cap enforced before allocation (WriteFrame,
//     ReadFrame and their raw forms);
//   - the canonical encoding for signed structures (MarshalCanonical): one
//     exact byte form per message, so signatures cover bytes both sides can
//     reproduce;
//   - conversions between the generated protobuf edge tag and dock
//     generation and their in-memory forms (TagToProtoV2, GenToProtoV2 and
//     their inverses), and nonce-free rendering of a generation (RedactGen);
//   - the lane stream attribution header and the lane datagram prefix
//     (AppendLaneHeader, ReadLaneHeader, AppendLaneDatagram,
//     ParseLaneDatagram), with the lane classes and stream security classes
//     they carry;
//   - the adapter-class bit assignments shared by admission records and
//     lane classes;
//   - dock connection error codes and stream kind bytes;
//   - zone admission lease parsing, validation, binding to an authenticated
//     peer, and signing (the zone-admission-lease/3 contract), plus the dock
//     proof that binds a lease to one TLS connection (the dock/3 contract);
//   - admission signer validation: the X.509-SVID profile a lease signer
//     must satisfy, the one signer identity each fabric plane accepts, and
//     chain verification against a caller-supplied trust bundle;
//   - the strict ECDSA P-256 lease-signature encoding: ASN.1 DER with a
//     canonical low-S value, so each signature has exactly one valid byte
//     form.
//
// The generated protobuf bindings live in the versioned subpackages
// (admissionv3, dockv3 and the others under this directory).
//
// The package is importable without a QUIC implementation: apart from the
// standard library it depends only on google.golang.org/protobuf, the
// generated bindings, and the generation types.
//
// # Nonce redaction
//
// A dock generation's nonce is its succession credential. No error, log
// line or rendered generation produced by this package contains it;
// generations render through RedactGen as edge_tag#slot.epoch.
package wire
