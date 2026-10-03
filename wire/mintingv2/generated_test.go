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

package mintingv2_test

import (
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/idyl-labs/hyperplane-go/wire/mintingv2"
)

// TestGeneratedAccessors checks two properties of every message in the
// package. Getters are nil-safe and return zero values on a nil message,
// which the validators rely on when they read an absent field. And each
// field set through protobuf reflection is visible through its getter and
// survives a binary round trip, so the generated code and the descriptor
// describe the same message.
func TestGeneratedAccessors(t *testing.T) {
	checkGeneratedAccessors(t, mintingv2.File_idyl_minting_v2_minting_proto)
}

func checkGeneratedAccessors(t *testing.T, file protoreflect.FileDescriptor) {
	t.Helper()
	messages := file.Messages()
	if messages.Len() == 0 {
		t.Fatal("file declares no messages")
	}
	for i := range messages.Len() {
		descriptor := messages.Get(i)
		messageType, err := protoregistry.GlobalTypes.FindMessageByName(descriptor.FullName())
		if err != nil {
			t.Fatalf("%s: %v", descriptor.FullName(), err)
		}
		goType := reflect.TypeOf(messageType.New().Interface())
		for _, value := range callGetters(reflect.Zero(goType)) {
			if !value.IsZero() {
				t.Errorf("%s: getter on a nil message returned %v", descriptor.FullName(), value)
			}
		}
		fields := descriptor.Fields()
		for j := range fields.Len() {
			field := fields.Get(j)
			message := messageType.New()
			message.Set(field, sampleValue(message, field))
			getter := reflect.ValueOf(message.Interface()).MethodByName("Get" + goCamelCase(string(field.Name())))
			if !getter.IsValid() {
				t.Fatalf("%s: no getter for field %s", descriptor.FullName(), field.Name())
			}
			if getter.Call(nil)[0].IsZero() {
				t.Errorf("%s: getter for set field %s returned the zero value", descriptor.FullName(), field.Name())
			}
			callGetters(reflect.ValueOf(message.Interface()))
			encoded, err := proto.Marshal(message.Interface())
			if err != nil {
				t.Fatalf("%s.%s: %v", descriptor.FullName(), field.Name(), err)
			}
			decoded := messageType.New().Interface()
			if err := proto.Unmarshal(encoded, decoded); err != nil {
				t.Fatalf("%s.%s: %v", descriptor.FullName(), field.Name(), err)
			}
			if !proto.Equal(decoded, message.Interface()) {
				t.Errorf("%s.%s: binary round trip changed the message", descriptor.FullName(), field.Name())
			}
			if message.Interface().(interface{ String() string }).String() == "" {
				t.Errorf("%s.%s: text rendering of a populated message is empty", descriptor.FullName(), field.Name())
			}
		}
	}
}

// callGetters calls every exported zero-argument Get method of message.
func callGetters(message reflect.Value) []reflect.Value {
	var results []reflect.Value
	for i := range message.NumMethod() {
		method := message.Type().Method(i)
		if !strings.HasPrefix(method.Name, "Get") || method.Type.NumIn() != 1 || method.Type.NumOut() != 1 {
			continue
		}
		results = append(results, message.Method(i).Call(nil)[0])
	}
	return results
}

// sampleValue returns a non-default value for field.
func sampleValue(message protoreflect.Message, field protoreflect.FieldDescriptor) protoreflect.Value {
	if field.IsList() {
		list := message.NewField(field).List()
		if field.Kind() == protoreflect.MessageKind || field.Kind() == protoreflect.GroupKind {
			list.Append(list.NewElement())
		} else {
			list.Append(sampleScalar(field))
		}
		return protoreflect.ValueOfList(list)
	}
	if field.Kind() == protoreflect.MessageKind || field.Kind() == protoreflect.GroupKind {
		return message.NewField(field)
	}
	return sampleScalar(field)
}

func sampleScalar(field protoreflect.FieldDescriptor) protoreflect.Value {
	switch field.Kind() {
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(true)
	case protoreflect.EnumKind:
		return protoreflect.ValueOfEnum(field.Enum().Values().Get(field.Enum().Values().Len() - 1).Number())
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return protoreflect.ValueOfInt32(1)
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64(1)
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(1)
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(1)
	case protoreflect.FloatKind:
		return protoreflect.ValueOfFloat32(1)
	case protoreflect.DoubleKind:
		return protoreflect.ValueOfFloat64(1)
	case protoreflect.StringKind:
		return protoreflect.ValueOfString("x")
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes([]byte{1})
	default:
		panic("unsupported field kind " + field.Kind().String())
	}
}

// goCamelCase converts a lower_snake_case field name to the Go name the
// protobuf code generator gives its getter.
func goCamelCase(name string) string {
	parts := strings.Split(name, "_")
	for i, part := range parts {
		if part != "" {
			parts[i] = strings.ToUpper(part[:1]) + part[1:]
		}
	}
	return strings.Join(parts, "")
}
