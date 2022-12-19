// Copyright 2019-2021 The Inspektor Gadget authors
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

package types

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type DNSPktType string

const (
	DNSPktTypeQuery    DNSPktType = "Q"
	DNSPktTypeResponse DNSPktType = "R"
)

// DNS header RCODE field.
// https://datatracker.ietf.org/doc/rfc1035#section-4.1.1
type DNSResponseCode uint8

const (
	DNSResponseCodeSuccess        DNSResponseCode = 0 // NoError
	DNSResponseCodeFormatError    DNSResponseCode = 1 // FormErr
	DNSResponseCodeServerFailure  DNSResponseCode = 2 // ServFail
	DNSResponseCodeNameError      DNSResponseCode = 3 // NXDomain
	DNSResponseCodeNotImplemented DNSResponseCode = 4 // NotImp
	DNSResponseCodeRefused        DNSResponseCode = 5 // Refused
)

func (rcode DNSResponseCode) String() string {
	switch rcode {
	case DNSResponseCodeSuccess:
		return "NoError"
	case DNSResponseCodeFormatError:
		return "FormErr"
	case DNSResponseCodeServerFailure:
		return "ServFail"
	case DNSResponseCodeNameError:
		return "NXDomain"
	case DNSResponseCodeNotImplemented:
		return "NotImp"
	case DNSResponseCodeRefused:
		return "Refused"
	default:
		return ""
	}
}

type Event struct {
	eventtypes.Event

	ID           string          `json:"id,omitempty" column:"id,width:4,fixed,hide"`
	Qr           DNSPktType      `json:"qr,omitempty" column:"qr,width:2,fixed"`
	Nameserver   string          `json:"nameserver,omitempty" column:"nameserver,template:ipaddr"`
	PktType      string          `json:"pktType,omitempty" column:"type,minWidth:7,maxWidth:9"`
	QType        string          `json:"qtype,omitempty" column:"qtype,minWidth:5,maxWidth:10"`
	DNSName      string          `json:"name,omitempty" column:"name,width:30"`
	ResponseCode DNSResponseCode `json:"responseCode,omitEmpty"  column:"responseCode"`
}

func GetColumns() *columns.Columns[Event] {
	cols := columns.MustCreateColumns[Event]()

	col, _ := cols.GetColumn("container")
	col.Visible = false

	return cols
}

func Base(ev eventtypes.Event) Event {
	return Event{
		Event: ev,
	}
}
