// Copyright 2019-2022 The Inspektor Gadget authors
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

package trace

import (
	"encoding/json"
	"fmt"
	"os"

	commontrace "github.com/inspektor-gadget/inspektor-gadget/cmd/common/trace"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"

	"github.com/spf13/cobra"
)

// TraceGadget represents a gadget belonging to the trace category.
type TraceGadget[Event commontrace.TraceEvent] struct {
	name        string
	commonFlags *utils.CommonFlags
	params      map[string]string
	parser      commontrace.TraceParser[Event]
}

// Run runs a TraceGadget and prints the output after parsing it using the
// TraceParser's methods.
func (g *TraceGadget[Event]) Run() error {
	config := &utils.TraceConfig{
		GadgetName:       g.name,
		Operation:        gadgetv1alpha1.OperationStart,
		TraceOutputMode:  gadgetv1alpha1.TraceOutputModeStream,
		TraceOutputState: gadgetv1alpha1.TraceStateStarted,
		CommonFlags:      g.commonFlags,
		Parameters:       g.params,
	}

	// Print header
	switch g.commonFlags.OutputMode {
	case commonutils.OutputModeJSON:
		// Nothing to print
	case commonutils.OutputModeColumns:
		fallthrough
	case commonutils.OutputModeCustomColumns:
		fmt.Println(g.parser.BuildColumnsHeader())
	}

	transformEvent := func(line string) string {
		var e Event

		if err := json.Unmarshal([]byte(line), &e); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s", commonutils.WrapInErrUnmarshalOutput(err, line))
			return ""
		}

		baseEvent := e.GetBaseEvent()
		if baseEvent.Type != eventtypes.NORMAL {
			commonutils.ManageSpecialEvent(baseEvent, g.commonFlags.Verbose)
			return ""
		}

		switch g.commonFlags.OutputMode {
		case commonutils.OutputModeJSON:
			b, err := json.Marshal(e)
			if err != nil {
				fmt.Fprint(os.Stderr, fmt.Sprint(commonutils.WrapInErrMarshalOutput(err)))
				return ""
			}

			return string(b)
		case commonutils.OutputModeColumns:
			fallthrough
		case commonutils.OutputModeCustomColumns:
			return g.parser.TransformIntoColumns(&e)
		default:
			fmt.Fprint(os.Stderr, commonutils.WrapInErrOutputModeNotSupported(g.commonFlags.OutputMode))
			return ""
		}
	}

	if err := utils.RunTraceAndPrintStream(config, transformEvent); err != nil {
		return commonutils.WrapInErrRunGadget(err)
	}

	return nil
}

func NewTraceCmd() *cobra.Command {
	traceCmd := commontrace.NewCommonTraceCmd()

	traceCmd.AddCommand(newBindCmd())
	traceCmd.AddCommand(newCapabilitiesCmd())
	traceCmd.AddCommand(newDNSCmd())
	traceCmd.AddCommand(newExecCmd())
	traceCmd.AddCommand(newFsSlowerCmd())
	traceCmd.AddCommand(newMountCmd())
	traceCmd.AddCommand(newNetworkCmd())
	traceCmd.AddCommand(newOOMKillCmd())
	traceCmd.AddCommand(newOpenCmd())
	traceCmd.AddCommand(newSignalCmd())
	traceCmd.AddCommand(newSNICmd())
	traceCmd.AddCommand(newTCPCmd())
	traceCmd.AddCommand(newTcpconnectCmd())
	traceCmd.AddCommand(newIptablesCmd())

	return traceCmd
}
