//go:build linux
// +build linux

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
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/iptables/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Tracer struct {
	ticker        *time.Ticker
	eventCallback func(types.Event)
}

func NewTracer(enricher gadgets.DataEnricher, eventCallback func(types.Event)) (*Tracer, error) {
	t := &Tracer{
		eventCallback: eventCallback,
	}

	if err := t.start(); err != nil {
		t.Stop()
		return nil, err
	}

	return t, nil
}

func (t *Tracer) Stop() {
	t.ticker.Stop()
}

func (t *Tracer) start() error {
	t.ticker = time.NewTicker(5 * time.Second)
	go t.run()
	return nil
}

func (t *Tracer) run() {
	var count uint64
	for {
		select {
		case <-t.ticker.C:
			t.eventCallback(types.Event{
				Event: eventtypes.Event{
					Type: eventtypes.NORMAL,
				},
				DebugCount: count,
			})
			count++
		}
	}
}
