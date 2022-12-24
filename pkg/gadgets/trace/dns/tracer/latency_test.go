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

func assertNumOutstandingRequests(t *testing.T, c *dnsLatencyCalculator, expected int) {
	n := c.numOutstandingRequests()
	if n != expected {
		t.Fatalf("Expected %d outstanding requests, but got %d", expected, n)
	}
}

func TestDnsLatencyCalculatorRequestResponse(t *testing.T) {
	addr := [16]uint8{1}
	id := uint16(1)
	c := newDnsLatencyCalculator()

	c.storeDnsRequestTimestamp(addr, id, 100)
	assertNumOutstandingRequests(t, c, 1)

	latency := c.calculateDnsResponseLatency(addr, id, 500)
	expectedLatency := 400 * time.Nanosecond
	if latency != expectedLatency {
		t.Fatalf("Expected latency %d but got %d", expectedLatency, latency)
	}
	assertNumOutstandingRequests(t, c, 0)
}

func TestDnsLatencyCalculatorResponseWithoutMatchingRequest(t *testing.T) {
	addr := [16]uint8{1}
	id := uint16(1)
	c := newDnsLatencyCalculator()

	// Response for an addr/id without a corresponding request.
	latency := c.calculateDnsResponseLatency(addr, id, 500)
	if latency != 0 {
		t.Fatalf("Expected zero latency but got %d", latency)
	}
	assertNumOutstandingRequests(t, c, 0)
}

func TestDnsLatencyCalculatorResponseWithSameIdButDifferentSrcIP(t *testing.T) {
	firstAddr, secondAddr := [16]uint8{1}, [16]uint8{2}
	id := uint16(1)
	c := newDnsLatencyCalculator()

	// Two requests, same ID, different IPs
	c.storeDnsRequestTimestamp(firstAddr, id, 100)
	c.storeDnsRequestTimestamp(secondAddr, id, 200)
	assertNumOutstandingRequests(t, c, 2)

	// Latency calculated correctly for both responses.
	latency := c.calculateDnsResponseLatency(firstAddr, id, 500)
	expectedLatency := 400 * time.Nanosecond
	if latency != expectedLatency {
		t.Fatalf("Expected latency %d but got %d", expectedLatency, latency)
	}

	latency = c.calculateDnsResponseLatency(secondAddr, id, 700)
	expectedLatency = 500 * time.Nanosecond
	if latency != expectedLatency {
		t.Fatalf("Expected latency %d but got %d", expectedLatency, latency)
	}
	assertNumOutstandingRequests(t, c, 0)
}

func TestDnsLatencyCalculatorManyOutstandingRequests(t *testing.T) {
	addr := [16]uint8{1}
	c := newDnsLatencyCalculator()

	var lastId uint16
	for i := 0; i < dnsLatencyMapSize*3; i++ {
		id := uint16(i)
		c.storeDnsRequestTimestamp(addr, id, 100)
		lastId = id
	}

	// Dropped some of the outstanding requests.
	assertNumOutstandingRequests(t, c, dnsLatencyMapSize * 2)

	// Response to most recent request should report latency.
	latency := c.calculateDnsResponseLatency(addr, lastId, 300)
	expectedLatency := 200 * time.Nanosecond
	if latency != expectedLatency {
		t.Fatalf("Expected latency %d but got %d", expectedLatency, latency)
	}

	// Response to first (dropped) requests should NOT report latency.
	latency = c.calculateDnsResponseLatency(addr, 0, 400)
	if latency != 0 {
		t.Fatalf("Expected zero latency but got %d", latency)
	}

	// Response to prior request that wasn't yet dropped should report latency.
	latency = c.calculateDnsResponseLatency(addr, lastId - uint16(dnsLatencyMapSize) - 1, 600)
	expectedLatency = 500 * time.Nanosecond
	if latency != expectedLatency {
		t.Fatalf("Expected latency %d but got %d", expectedLatency, latency)
	}
}

func TestDnsLatencyCalculatorResponseWithZeroTimestamp(t *testing.T) {
	addr := [16]uint8{1}
	id := uint16(1)
	c := newDnsLatencyCalculator()

	c.storeDnsRequestTimestamp(addr, id, 100)
	assertNumOutstandingRequests(t, c, 1)

	// Response has timestamp zero (should never happen, but check it anyway to prevent overflow).
	latency := c.calculateDnsResponseLatency(addr, id, 0)
	if latency != 0 {
		t.Fatalf("Expected zero latency but got %d", latency)
	}
	assertNumOutstandingRequests(t, c, 0)
}
