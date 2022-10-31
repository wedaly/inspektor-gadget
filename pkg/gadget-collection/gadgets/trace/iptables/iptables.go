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

	// TODO: explain this
	err = netnsenter.NetnsEnter(pid, func() error {
		rule := containerNetNsIptablesRule(trace)
		return ipt.Append(rule[0], rule[1], rule[2:]...)
	})
	if err != nil {
		return err
	}

	// TODO: explain this
	rule := hostNetnsIptablesRule(iface, trace)
	err = ipt.Append(rule[0], rule[1], rule[2:]...)
	if err != nil {
		return err
	}

	return nil
}

func removeIptablesTraceRules(trace *gadgetv1alpha1.Trace) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	// TODO: explain this
	err = netnsenter.NetnsEnter(pid, func() error {
		rule := containerNetNsIptablesRule(trace)
		return ipt.Append(rule[0], rule[1], rule[2:]...)
	})
	if err != nil {
		return err
	}

	// TODO: explain this
	rule := hostNetnsIptablesRule(iface, trace)
	err = ipt.DeleteIfExists(rule[0], rule[1], rule[2:]...)
	if err != nil {
		return err
	}

	return nil
}

func containerNetNsIptablesRule(trace *gadgetv1alpha1.Trace) []string {
	return []string{
		"raw", "OUTPUT",
		"-p", "tcp", "--syn",
		"-m", "comment", "--comment", iptablesCommentFromTrace(trace),
		"-j", "TRACE",
	}
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
