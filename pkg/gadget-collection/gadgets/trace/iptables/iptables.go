package iptables

import (
	"fmt"

	"github.com/coreos/go-iptables/iptables"
	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/netnsenter"
)

func installIptablesTraceRules(trace *gadgetv1alpha1.Trace, helpers gadgets.GadgetHelpers) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	for _, container := range helpers.GetContainersBySelector(trace.Spec.Filter) {
		// TODO: explain this
		hostRule := hostNetnsIptablesTraceRule(c.VethPeerName, trace)
		err = ipt.Append(hostRule[0], hostRule[1], hostRule[2:]...)
		if err != nil {
			return err
		}

		// TODO: explain this
		err = netnsenter.NetnsEnter(c.Pid, func() error {
			rule := containerNetNsIptablesTraceRule(trace)
			return ipt.Append(rule[0], rule[1], rule[2:]...)
		})
		if err != nil {
			ipt.DeleteIfExists(hostRule[0], hostRule[1], hostRule[2:]...) // TODO: explain this...
			return err
		}
	}

	return nil
}

func removeIptablesTraceRules(trace *gadgetv1alpha1.Trace, helpers gadgets.GadgetHelpers) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	for _, container := range helpers.GetContainersBySelector(trace.Spec.Filter) {
		// TODO: explain this
		hostRule := hostNetnsIptablesTraceRule(c.VethPeerName, trace)
		err = ipt.DeleteIfExists(hostRule[0], hostRule[1], hostRule[2:]...)
		if err != nil {
			return err
		}

		// TODO: explain this
		// TODO: what happens if this fails b/c the container was deleted...? probably log a warning?
		err = netnsenter.NetnsEnter(c.Pid, func() error {
			rule := containerNetNsIptablesTraceRule(trace)
			return ipt.Append(rule[0], rule[1], rule[2:]...)
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func validateFilterSelectsOneContainer(filter *gadgetv1alpha1.ContainerFilter) error {
	if filter == nil || filter.Namespace == "" || filter.Podname == "" {
		return fmt.Errorf("Missing pod")
	}
	return nil
}

func containerNetNsIptablesTraceRule(trace *gadgetv1alpha1.Trace) []string {
	return []string{
		"raw", "OUTPUT",
		"-p", "tcp", "--syn",
		"-m", "comment", "--comment", iptablesCommentFromTrace(trace),
		"-j", "TRACE",
	}
}

func hostNetnsIptablesTraceRule(iface string, trace *gadgetv1alpha1.Trace) []string {
	return []string{
		"raw", "PREROUTING",
		"-i", iface,
		"-p", "tcp", "--syn", // TODO: other packets too?
		"-m", "comment", "--comment", iptablesCommentFromTrace(trace),
		"-j", "TRACE",
	}
}

func iptablesCommentFromTrace(trace *gadgetv1alpha1.Trace) string {
	comment := fmt.Sprintf("IG-Trace=%s/%s", trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)
	// iptables allow only 256 characters
	if len(comment) > 256 {
		comment = comment[0:256]
	}
	return comment
}
