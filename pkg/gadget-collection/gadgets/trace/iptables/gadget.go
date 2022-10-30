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

package iptables

import (
	"encoding/json"
	"fmt"

	"github.com/coreos/go-iptables/iptables"
	log "github.com/sirupsen/logrus"

	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets/trace"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/iptables/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/iptables/types"
)

type Trace struct {
	helpers gadgets.GadgetHelpers

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
	return `iptables traces which iptables rules are processed for packets` // TODO: ingress/egress?
}

func (f *TraceFactory) OutputModesSupported() map[gadgetv1alpha1.TraceOutputMode]struct{} {
	return map[gadgetv1alpha1.TraceOutputMode]struct{}{
		gadgetv1alpha1.TraceOutputModeStream: {},
	}
}

func deleteTrace(name string, t any) {
	trace := t.(*Trace)
	if trace.tracer != nil {
		trace.tracer.Stop()
	}
}

func (f *TraceFactory) Operations() map[gadgetv1alpha1.Operation]gadgets.TraceOperation {
	n := func() interface{} {
		return &Trace{
			helpers: f.Helpers,
		}
	}

	return map[gadgetv1alpha1.Operation]gadgets.TraceOperation{
		gadgetv1alpha1.OperationStart: {
			Doc: "Start iptables gadget",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
		gadgetv1alpha1.OperationStop: {
			Doc: "Stop iptables gadget",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Stop(trace)
			},
		},
	}
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	if t.started {
		trace.Status.State = gadgetv1alpha1.TraceStateStarted
	}

	traceName := gadgets.TraceName(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)

	eventCallback := func(event types.Event) {
		r, err := json.Marshal(event)
		if err != nil {
			log.Warnf("Gadget %s: error marshalling event: %s", trace.Spec.Gadget, err)
			return
		}
		t.helpers.PublishEvent(traceName, string(r))
	}

	tracer, err := tracer.NewTracer(t.helpers, eventCallback)
	if err != nil {
		trace.Status.OperationError = fmt.Sprint("failed to create tracer: %s", err)
		return
	}

	if err := t.installIptablesTraceRules(trace); err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed to install iptables TRACE rules: %s", err)
		tracer.Stop()
		return
	}

	t.tracer = tracer
	t.started = true
	trace.Status.State = gadgetv1alpha1.TraceStateStarted
}

func (t *Trace) Stop(trace *gadgetv1alpha1.Trace) {
	if !t.started {
		trace.Status.OperationError = "Not started"
		return
	}

	if err := t.removeIptablesTraceRules(trace); err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed to remove iptables TRACE rules: %s", err)
		return
	}

	t.tracer.Stop()
	t.tracer = nil
	t.started = false
	trace.Status.State = gadgetv1alpha1.TraceStateStopped
}

func (t *Trace) installIptablesTraceRules(trace *gadgetv1alpha1.Trace) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	// TODO: find the host veth pair based on trace filters...
	// TODO: install iptables rule RAW PREROUTING

	// TODO: find netns for container
	// TODO: enter netns for container
	// TODO: install iptables TRACE rule RAW OUTPUT

	return nil
}

func (t *Trace) removeIptablesTraceRules(trace *gadgetv1alpha1.Trace) error {
	// TODO: remove all installed iptables rules
	return nil
}
