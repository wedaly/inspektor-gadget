package iptables

import (
	"fmt"

	"github.com/coreos/go-iptables/iptables"
	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/netnsenter"
)

func installIptablesTraceRules(trace *gadgetv1alpha1.Trace) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	if err := installContainerNetnsRawOutputIptablesRule(trace, ipt); err != nil {
		return err
	}

	if err := installHostNetnsRawPreroutingIptablesRule(trace, ipt); err != nil {
		return err
	}

	return nil
}

func removeIptablesTraceRules(trace *gadgetv1alpha1.Trace) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	if err := removeContainerNetsRawOutputIptablesRule(trace, ipt); err != nil {
		return err
	}

	if err := removeHostNetnsRawPreroutingIptablesRule(trace, ipt); err != nil {
		return err
	}

	return nil
}

func installContainerNetnsRawOutputIptablesRule(trace *gadgetv1alpha1.Trace, ipt *iptables.IPTables) error {
	// TODO: how to find the pid for the pod netns?
	rule := containerNetNsIptablesRule(trace)
	return netnsenter.NetnsEnter(pid, func() error {
		return ipt.Append(rule[0], rule[1], rule[2:]...)
	})
}

func removeContainerNetsRawOutputIptablesRule(trace *gadgetv1alpha1.Trace, ipt *iptables.IPTables) error {
	// TODO: how to find the pid for the pod netns?
	rule := containerNetNsIptablesRule(trace)
	return netnsenter.NetnsEnter(pid, func() error {
		return ipt.DeleteIfExists(rule[0], rule[1], rule[2:]...)
	})
}

func containerNetNsIptablesRule(trace *gadgetv1alpha1.Trace) []string {
	return []string{
		"raw", "OUTPUT",
		"-p", "tcp", "--syn",
		"-m", "comment", "--comment", iptablesCommentFromTrace(trace),
		"-j", "TRACE",
	}
}

func installHostNetnsRawPreroutingIptablesRule(trace *gadgetv1alpha1.Trace, ipt *iptables.IPTables) error {
	// TODO: how to get iface
	rule := hostNetnsIptablesRule(iface, trace)
	return ipt.Append(rule[0], rule[1], rule[2:]...)
}

func removeHostNetnsRawPreroutingIptablesRule(trace *gadgetv1alpha1.Trace, ipt *iptables.IPTables) error {
	// TODO: how to get iface
	rule := hostNetnsIptablesRule(iface, trace)
	return ipt.DeleteIfExists(rule[0], rule[1], rule[2:]...)
}

func hostNetnsIptablesRule(iface string, trace *gadgetv1alpha1.Trace) []string {
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
	// iptables only allow 256 characters
	if len(comment) > 256 {
		comment = comment[0:256]
	}
	return comment
}
