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
		return ipt.Append(rule.table, rule.chain, rule.spec...)
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

func iptablesRules(trace *gadgetv1alpha1.Trace, helpers gadgets.GadgetHelpers) []iptablesRule {
	var rules []iptablesRule
	comment := iptablesCommentFromTrace(trace)
	selector := gadgets.ContainerSelectorFromContainerFilter(trace.Spec.Filter)
	for _, c := range helpers.GetContainersBySelector(selector) {
		if c.VethPeerName == "" {
			log.Warnf("Gadget %s: skipping container %s because its VethPeerName is empty", trace.Spec.Gadget, c.ID)
			continue
		}

		rules = append(
			rules,
			iptablesRule{
				containerPid: int(c.Pid),
				table:        "raw",
				chain:        "OUTPUT",
				spec: []string{
					"-p", "tcp", "--syn",
					"-m", "comment", "--comment", comment,
					"-j", "TRACE",
				},
			},
			iptablesRule{
				table: "raw",
				chain: "OUTPUT",
				spec: []string{
					"-i", c.VethPeerName,
					"-p", "tcp", "--syn",
					"-m", "comment", "--comment", comment,
					"-j", "TRACE",
				},
			})

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
