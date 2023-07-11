// Copyright 2019-2023 The Inspektor Gadget authors
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

//go:build !withoutebpf

package tracer

import (
	"time"

	"github.com/cilium/ebpf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	log "github.com/sirupsen/logrus"
)

type garbageCollector struct {
	started  bool
	doneChan chan struct{}
	queryMap *ebpf.Map
}

func newGarbageCollector(queryMap *ebpf.Map) *garbageCollector {
	return &garbageCollector{queryMap: queryMap}
}

func (gc *garbageCollector) start() {
	if gc.started {
		return
	}

	log.Infof("Starting garbage collection for DNS tracer")
	gc.doneChan = make(chan struct{}, 0)
	go gc.runLoop()
	gc.started = true
}

func (gc *garbageCollector) stop() {
	if !gc.started {
		return
	}

	log.Infof("Stopping garbage collection for DNS tracer")
	close(gc.doneChan)
	gc.started = false
}

func (gc *garbageCollector) runLoop() {
	for {
		select {
		case <-gc.doneChan:
			return

		default:
			log.Infof("Executing DNS query map garbage collection")
			gc.collect()
			time.Sleep(5 * time.Second) // TODO: make configurable...
		}
	}
}

func (gc *garbageCollector) collect() {
	var (
		key          dnsQueryKeyT
		val          dnsQueryTsT
		keysToDelete []dnsQueryKeyT
	)
	cutoffTs := types.Time(time.Now().Add(-10 * time.Second).UnixNano())
	iter := gc.queryMap.Iterate()
	// TODO: comment about this possibly getting aborted or repeating keys if concurrent deletes...
	for iter.Next(&key, &val) {
		ts := gadgets.WallTimeFromBootTime(val.Timestamp)
		if ts < cutoffTs {
			keysToDelete = append(keysToDelete, key)
		}
	}

	if err := iter.Err(); err != nil {
		if err == ebpf.ErrIterationAborted {
			log.Warnf("Received ErrIterationAborted when iterating through DNS query map, possibly due to concurrent deletes. Some entries may be skipped this garbage collection cycle.")
		} else {
			log.Errorf("Received err %s when iterating through DNS query map", err)
		}
	}

	for _, key := range keysToDelete {
		log.Infof("Deleting key with mntNs=%d and DNS ID=%d from query map for DNS tracer", key.MountNsId, key.Id)
		err := gc.queryMap.Delete(key)
		if err != nil {
			log.Errorf("Could not delete DNS query timestamp with key mntNs=%d and DNS ID=%d", key.MountNsId, key.Id)
		}
	}
}
