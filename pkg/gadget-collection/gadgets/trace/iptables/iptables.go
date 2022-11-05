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
	"fmt"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/netnsenter"
	log "github.com/sirupsen/logrus"
)

type iptablesRule struct {
	containerPid int // zero for host netns
	table        string
	chain        string
	spec         []string
}

func (rule iptablesRule) install(ipt *iptables.IPTables) error {
	// If containerPid is zero, NetnsEnter does nothing (stay in host netns).
	return netnsenter.NetnsEnter(rule.containerPid, func() error {
		return ipt.AppendUnique(rule.table, rule.chain, rule.spec...)
	})
}

func (rule iptablesRule) remove(ipt *iptables.IPTables) error {
	// If containerPid is zero, NetnsEnter does nothing (stay in host netns).
	return netnsenter.NetnsEnter(rule.containerPid, func() error {
		return ipt.DeleteIfExists(rule.table, rule.chain, rule.spec...)
	})
}

func (rule iptablesRule) String() string {
	return fmt.Sprintf(
		"containerPid=%d, table=%s, chain=%s, spec=%q",
		rule.containerPid,
		rule.table,
		rule.chain,
		strings.Join(rule.spec, " "))
}

func iptablesTraceRules(trace *gadgetv1alpha1.Trace, helpers gadgets.GadgetHelpers) []iptablesRule {
	var rules []iptablesRule
	comment := iptablesCommentFromTrace(trace)
	selector := gadgets.ContainerSelectorFromContainerFilter(trace.Spec.Filter)
	for _, c := range helpers.GetContainersBySelector(selector) {
		if c.VethPeerName == "" {
			log.Warnf("Gadget %s: skipping container %s because its VethPeerName is empty", trace.Spec.Gadget, c.ID)
			continue
		}

		rulesForContainer := []iptablesRule{
			// TCP SYN packets leaving container netns
			{
				containerPid: int(c.Pid),
				table:        "raw",
				chain:        "OUTPUT",
				spec: []string{
					"-p", "tcp", "--syn",
					"-m", "comment", "--comment", comment,
					"-j", "TRACE",
				},
			},

			// ICMP packets leaving container netns
			{
				containerPid: int(c.Pid),
				table:        "raw",
				chain:        "OUTPUT",
				spec: []string{
					"-p", "icmp",
					"-m", "comment", "--comment", comment,
					"-j", "TRACE",
				},
			},

			// TCP SYN packets arriving at host netns from container veth
			{
				table: "raw",
				chain: "PREROUTING",
				spec: []string{
					"-i", c.VethPeerName,
					"-p", "tcp", "--syn",
					"-m", "comment", "--comment", comment,
					"-j", "TRACE",
				},
			},

			// ICMP packets arriving at host netns from container veth
			{
				table: "raw",
				chain: "PREROUTING",
				spec: []string{
					"-i", c.VethPeerName,
					"-p", "icmp",
					"-m", "comment", "--comment", comment,
					"-j", "TRACE",
				},
			},
		}

		rules = append(rules, rulesForContainer...)
	}

	return rules
}

func iptablesCommentFromTrace(trace *gadgetv1alpha1.Trace) string {
	comment := fmt.Sprintf("IG-Trace=%s/%s", trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)
	// iptables allow only 256 characters
	if len(comment) > 256 {
		comment = comment[0:256]
	}
	return comment
}
