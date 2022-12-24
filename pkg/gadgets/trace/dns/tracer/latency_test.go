// Copyright 2022 The Inspektor Gadget authors
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

package tracer

import (
	"testing"
	"time"
)

func TestDnsLatencyCalculatorRequestResponse(t *testing.T) {
	addr := [16]uint8{1}
	id := uint16(1)
	c := newDnsLatencyCalculator()
	c.storeDnsRequestTimestamp(addr, id, 100)
	latency := c.calculateDnsResponseLatency(addr, id, 500)
	expectedLatency := 400 * time.Nanosecond
	if latency != expectedLatency {
		t.Fatalf("Expected latency %d but got %d", expectedLatency, latency)
	}
}
