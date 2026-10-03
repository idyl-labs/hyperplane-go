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

import (
	"testing"
	"time"
)

// Every keepalive draw lands inside [65%, 80%] of the granted cadence, so
// no keepalive fires later than the 80% bound the edge's detection window
// relies on. Successive draws also vary, so a population of docks cannot
// settle into a common phase.
func TestKeepaliveDelayStaysInsideTheGrantWindow(t *testing.T) {
	for _, granted := range []time.Duration{
		time.Second,
		8 * time.Second,
		15 * time.Second,
		80 * time.Second,
		300 * time.Second,
	} {
		floor := granted * keepaliveJitterFloorPct / 100
		ceil := granted * keepaliveJitterCeilPct / 100
		distinct := map[time.Duration]bool{}
		var sum time.Duration
		const draws = 4096
		for i := 0; i < draws; i++ {
			d := keepaliveDelay(granted)
			if d < floor || d > ceil {
				t.Fatalf("granted %v: draw %v outside [%v, %v]", granted, d, floor, ceil)
			}
			distinct[d] = true
			sum += d
		}
		if len(distinct) < 64 {
			t.Fatalf("granted %v: only %d distinct draws in %d; the cadence is not jittered", granted, len(distinct), draws)
		}
		// The mean sits near the window center, which bounds the extra
		// send rate the jitter costs relative to a fixed 80% interval
		// (about a tenth more keepalives).
		mean := sum / draws
		lo := granted * 70 / 100
		hi := granted * 75 / 100
		if mean < lo || mean > hi {
			t.Fatalf("granted %v: mean draw %v outside [%v, %v]", granted, mean, lo, hi)
		}
	}
}
