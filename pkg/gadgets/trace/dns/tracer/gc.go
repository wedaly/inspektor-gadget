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

	gc.doneChan = make(chan struct{}, 0)
	go gc.runLoop()
	gc.started = true
}

func (gc *garbageCollector) stop() {
	if !gc.started {
		return
	}

	close(gc.doneChan)
	gc.started = false
}

func (gc *garbageCollector) runLoop() {
	for {
		select {
		case <-gc.doneChan:
			return

		default:
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

	// TODO: check iter error

	for _, key := range keysToDelete {
		err := gc.queryMap.Delete(key)
		if err != nil {
			panic(err) // TODO
		}
	}
}
