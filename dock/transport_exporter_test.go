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

package dock

// The transport fakes in this package's tests return a zeroed exporter of
// the requested length. Tests that assert on the exporter value use
// openingConn, which records each call and returns a chosen value.
func testExporter(length int) []byte { return make([]byte, length) }

func (*acceptConn) ExportKeyingMaterial(_ string, _ []byte, length int) ([]byte, error) {
	return testExporter(length), nil
}

func (*laneConn) ExportKeyingMaterial(_ string, _ []byte, length int) ([]byte, error) {
	return testExporter(length), nil
}
