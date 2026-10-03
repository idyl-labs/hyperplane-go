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

import (
	"errors"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// canonical.go: the canonical encoding for signed structures. Admission
// lease envelopes and payloads, dock proof inputs and the dock opening
// use it: every present field is emitted exactly once in ascending
// field-number order, no unknown fields are present, and ordering is
// deterministic throughout (the canonical messages use no maps). Golden
// vectors fix the exact bytes, so a protobuf-runtime change that altered
// the canonical form fails a test instead of silently invalidating
// signatures.

// MarshalCanonical serializes a signed structure in the canonical
// encoding. A message carrying unknown fields cannot be canonical, because
// it would re-emit bytes whose order this encoder does not control, so it
// is rejected; canonical structures are always built fresh by their
// producer.
func MarshalCanonical(m proto.Message) ([]byte, error) {
	if err := rejectUnknown(m.ProtoReflect()); err != nil {
		return nil, err
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(m)
}

// rejectUnknown refuses unknown bytes at any depth: a nested message
// retains and re-emits its unknown fields through the deterministic
// marshal exactly as the root would, so canonicality is judged over the
// whole message tree, never the root alone.
func rejectUnknown(m protoreflect.Message) error {
	if len(m.GetUnknown()) > 0 {
		return errors.New("wire: message with unknown fields cannot be canonically encoded")
	}
	var err error
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsMap():
			// The canonical messages use no maps; maps are walked anyway
			// so this check never depends on that convention.
			if fd.MapValue().Kind() == protoreflect.MessageKind {
				v.Map().Range(func(_ protoreflect.MapKey, mv protoreflect.Value) bool {
					err = rejectUnknown(mv.Message())
					return err == nil
				})
			}
		case fd.IsList():
			if fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind {
				list := v.List()
				for i := 0; i < list.Len(); i++ {
					if err = rejectUnknown(list.Get(i).Message()); err != nil {
						break
					}
				}
			}
		case fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind:
			err = rejectUnknown(v.Message())
		}
		return err == nil
	})
	return err
}
