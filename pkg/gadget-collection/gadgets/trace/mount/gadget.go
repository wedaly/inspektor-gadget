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

package mountsnoop

import (
	"encoding/json"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets"
	"github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/trace"

	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/mount/tracer"
	standardtracer "github.com/kinvolk/inspektor-gadget/pkg/standardgadgets/trace/mount"

	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/mount/types"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
)

type Trace struct {
	resolver gadgets.Resolver

	started bool
	tracer  trace.Tracer
}

type TraceFactory struct {
	gadgets.BaseFactory
}

func NewFactory() gadgets.TraceFactory {
	return &TraceFactory{
		BaseFactory: gadgets.BaseFactory{DeleteTrace: deleteTrace},
	}
}

func (f *TraceFactory) Description() string {
	return `mountsnoop traces mount and umount syscalls`
}

func (f *TraceFactory) OutputModesSupported() map[string]struct{} {
	return map[string]struct{}{
		"Stream": {},
	}
}

func deleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	if trace.tracer != nil {
		trace.tracer.Stop()
	}
}

func (f *TraceFactory) Operations() map[string]gadgets.TraceOperation {
	n := func() interface{} {
		return &Trace{
			resolver: f.Resolver,
		}
	}

	return map[string]gadgets.TraceOperation{
		"start": {
			Doc: "Start mountsnoop gadget",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
		"stop": {
			Doc: "Stop mountsnoop gadget",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Stop(trace)
			},
		},
	}
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	if t.started {
		trace.Status.State = "Started"
		return
	}

	traceName := gadgets.TraceName(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)

	eventCallback := func(event types.Event) {
		r, err := json.Marshal(event)
		if err != nil {
			log.Warnf("Gadget %s: error marshalling event: %s", trace.Spec.Gadget, err)
			return
		}
		t.resolver.PublishEvent(traceName, string(r))
	}

	var err error

	mountNsMap, err := t.resolver.TracerMountNsMap(traceName)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed to find tracer's mount ns map: %s", err)
		return
	}
	config := &tracer.Config{
		MountnsMap: mountNsMap,
	}
	t.tracer, err = tracer.NewTracer(config, t.resolver, eventCallback, trace.Spec.Node)
	if err != nil {
		trace.Status.OperationWarning = fmt.Sprint("failed to create core tracer. Falling back to standard one")

		// fallback to standard tracer
		log.Infof("Gadget %s: falling back to standard tracer. CO-RE tracer failed: %s",
			trace.Spec.Gadget, err)

		t.tracer, err = standardtracer.NewTracer(config, t.resolver, eventCallback, trace.Spec.Node)
		if err != nil {
			trace.Status.OperationError = fmt.Sprintf("failed to create tracer: %s", err)
			return
		}
	}

	t.started = true

	trace.Status.State = "Started"
}

func (t *Trace) Stop(trace *gadgetv1alpha1.Trace) {
	if !t.started {
		trace.Status.OperationError = "Not started"
		return
	}

	t.tracer.Stop()
	t.tracer = nil
	t.started = false

	trace.Status.State = "Stopped"
}
