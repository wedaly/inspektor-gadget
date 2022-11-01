package iptables

import (
	"fmt"

	"github.com/coreos/go-iptables/iptables"
	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/netnsenter"
	log "github.com/sirupsen/logrus"
)

type iptablesCleanupFunc func()

func installIptablesTraceRules(trace *gadgetv1alpha1.Trace, helpers gadgets.GadgetHelpers) (iptablesCleanupFunc, error) {
	var cleanupFuncs []iptablesCleanupFunc

	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	selector := gadgets.ContainerSelectorFromContainerFilter(trace.Spec.Filter)
	for _, c := range helpers.GetContainersBySelector(selector) {
		containerId := c.ID // Copy for reference in cleanup func.

		if c.VethPeerName == "" {
			log.Warnf("Gadget %s: skipping container %s because its VethPeerName is empty", trace.Spec.Gadget, containerID)
			continue
		}

		// TODO: explain this
		hostRule := hostNetnsIptablesTraceRule(c.VethPeerName, trace)
		err = ipt.Append(hostRule[0], hostRule[1], hostRule[2:]...)
		if err != nil {
			return err
		}
		cleanupFuncs = append(cleanupFuncs, func() {
			err := ipt.DeleteIfExists(hostRule[0], hostRule[1], hostRule[2:]...)
			if err != nil {
				log.Warnf("could not delete iptables rule %s:%s in host netns", hostRule[0], hostRule[1])
			}
		})

		// TODO: explain this
		containerRule := containerNetNsIptablesTraceRule(trace)
		err = netnsenter.NetnsEnter(int(c.Pid), func() error {
			return ipt.Append(containerRule[0], containerRule[1], containerRule[2:]...)
		})
		if err != nil {
			// On failure, rollback the host netns rule we created earlier.
			ipt.DeleteIfExists(hostRule[0], hostRule[1], hostRule[2:]...)
			return err
		}
		cleanupFuncs = append(cleanupFuncs, func() {
			err := ipt.DeleteIfExists(containerRule[0], containerRule[1], containerRule[2:]...)
			if err != nil {
				log.Warnf("could not delete iptables rule %s:%s in container %s netns", containerRule[0], containerRule[1], containerID)
			}
		}
	}

	fullCleanupFunc := func() {
		for _, f := range cleanupFuncs {
			f()
		}
	}
	return fullCleanupFunc, nil
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
