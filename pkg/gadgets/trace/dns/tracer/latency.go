// TODO: copyright...

package tracer

import "time"

const (
	dnsLatencyMapSize         int    = 64
	dnsReqTsMapRotateInterval uint64 = 5_000_000_000 // 5e+9 ns = 5 seconds
)

// TODO
type dnsReqKey struct {
	addr [16]uint8
	id   uint64
}

// TODO
type dnsLatencyCalculator struct {
	currentReqTsMap map[dnsReqKey]uint64
	prevReqTsMap    map[dnsReqKey]uint64
}

func newDnsLatencyCalculator() *dnsLatencyCalculator {
	return &dnsLatencyCalculator{
		lastRotateTimestamp: 0,
		currentReqTsMap:     make(map[dnsReqKey]uint64, dnsLatencyMapSize),
		prevReqTsMap:        nil,
	}
}

// TODO
func (c *dnsLatencyCalculator) storeDnsRequestTimestamp(saddr [16]uint8, id uint64, timestamp uint64) {
	// If the current map is full, drop the previous map and allocate a new one to make space.
	if len(c.currentReqTsMap) == dnsLatencyMapSize {
		c.prevReqTsMap = c.currentReqTsMap
		c.currentReqTsMap = make(map[dnsReqKey]uint64, dnsLatencyMapSize)
		c.lastRotateTimestamp = timestamp
	}

	// Store the timestamp of the request so we can calculate the latency once the response arrives.
	key := dnsReqKey{saddr, id}
	c.currentReqTsMap[key] = timestamp
}

// TODO
func (c *dnsLatencyCalculator) calculateDnsResponseLatency(daddr [16]uint8, id uint64, timestamp uint64) time.Duration {
	// Lookup the request timestamp so we can subtract it from the response timestamp.
	key := dnsReqKey{daddr, id}
	reqTs, ok := c.currentReqTsMap[key]
	if ok {
		// Found the request in the current map, so delete the entry to free space.
		delete(c.currentReqTsMap, key)
	} else if c.prevReqTsMap != nil {
		reqTs, ok = c.prevReqTsMap[key]
		if !ok {
			// Either an invalid ID or we evicted the request from the map to free space.
			return 0
		}
		// Don't bother deleting the entry because we've stopped adding new entries to prevReqTsMap.
	}

	if timestamp > reqTs {
		// Should never happen assuming timestamps are monotonic, but handle it just in case.
		return 0
	}

	return time.Duration(timestamp - reqTs)
}
