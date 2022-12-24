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

func assertLatency(t *testing.T, actual time.Duration, expected time.Duration) {
	if actual != expected {
		t.Fatalf("Expected latency %d but got %d", expected, actual)
	}
}

func assertNoLatency(t *testing.T, actual time.Duration) {
	if actual != 0 {
		t.Fatalf("Expected no latency returned, but got %d", actual)
	}
}

func TestDnsLatencyCalculatorRequestResponse(t *testing.T) {
	addr := [16]uint8{1}
	id := uint16(1)
	c := newDnsLatencyCalculator()

	c.storeDnsRequestTimestamp(addr, id, 100)
	assertNumOutstandingRequests(t, c, 1)

	latency := c.calculateDnsResponseLatency(addr, id, 500)
	assertLatency(t, latency, 400 * time.Nanosecond)
	assertNumOutstandingRequests(t, c, 0)
}

func TestDnsLatencyCalculatorResponseWithoutMatchingRequest(t *testing.T) {
	addr := [16]uint8{1}
	id := uint16(1)
	c := newDnsLatencyCalculator()

	// Response for an addr/id without a corresponding request.
	latency := c.calculateDnsResponseLatency(addr, id, 500)
	assertNoLatency(t, latency)
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
	firstLatency := c.calculateDnsResponseLatency(firstAddr, id, 500)
	assertLatency(t, firstLatency, 400 * time.Nanosecond)
	secondLatency := c.calculateDnsResponseLatency(secondAddr, id, 700)
	assertLatency(t, secondLatency, 500 * time.Nanosecond)
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
	assertLatency(t, latency, 200 * time.Nanosecond)

	// Response to first (dropped) requests should NOT report latency.
	latency = c.calculateDnsResponseLatency(addr, 0, 400)
	assertNoLatency(t, latency)

	// Response to prior request that wasn't yet dropped should report latency.
	latency = c.calculateDnsResponseLatency(addr, lastId - uint16(dnsLatencyMapSize) - 1, 600)
	assertLatency(t, latency, 500 * time.Nanosecond)
}

func TestDnsLatencyCalculatorResponseWithZeroTimestamp(t *testing.T) {
	addr := [16]uint8{1}
	id := uint16(1)
	c := newDnsLatencyCalculator()

	c.storeDnsRequestTimestamp(addr, id, 100)
	assertNumOutstandingRequests(t, c, 1)

	// Response has timestamp zero (should never happen, but check it anyway to prevent overflow).
	latency := c.calculateDnsResponseLatency(addr, id, 0)
	assertNoLatency(t, latency)
	assertNumOutstandingRequests(t, c, 0)
}
