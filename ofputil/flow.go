package ofputil

import (
	of "github.com/sensify-security/openflow"
	"github.com/sensify-security/openflow/ofp"
)

func TableFlush(table ofp.Table) *of.Request {
	return of.NewRequest(of.TypeFlowMod, &ofp.FlowMod{
		Table:    table,
		Command:  ofp.FlowDelete,
		Buffer:   ofp.NoBuffer,
		OutPort:  ofp.PortAny,
		OutGroup: ofp.GroupAny,
		Match:    ofp.Match{ofp.MatchTypeXM, nil},
	})
}

func FlowFlush(table ofp.Table, match ofp.Match) *of.Request {
	return of.NewRequest(of.TypeFlowMod, &ofp.FlowMod{
		Table:    table,
		Command:  ofp.FlowDelete,
		Buffer:   ofp.NoBuffer,
		OutPort:  ofp.PortAny,
		OutGroup: ofp.GroupAny,
		Match:    match,
	})
}

func FlowDrop(table ofp.Table) *of.Request {
	return of.NewRequest(of.TypeFlowMod, &ofp.FlowMod{
		Table:   table,
		Command: ofp.FlowAdd,
		Buffer:  ofp.NoBuffer,
		Match:   ofp.Match{ofp.MatchTypeXM, nil},
	})
}
