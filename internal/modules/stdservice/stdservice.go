// Package stdservice compiles std.service.Unit resources into Service ops.
package stdservice

import (
	"fmt"

	"github.com/claymod/claymod/internal/modules"
	"github.com/claymod/claymod/internal/playbook"
	"github.com/claymod/claymod/internal/proto"
)

// UnitResource mirrors the std.service.Unit PKL class.
type UnitResource struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Unit    string `json:"unit"`
	State   string `json:"state"`
	Enabled *bool  `json:"enabled"`
}

// compileUnit emits a single Service op.
func compileUnit(res playbook.Resource, ctx playbook.RenderContext) ([]proto.Op, error) {
	var r UnitResource
	if err := modules.DecodeResource(res, &r); err != nil {
		return nil, err
	}
	if r.Unit == "" {
		return nil, fmt.Errorf("unit is required")
	}
	switch r.State {
	case "", proto.StateStarted, proto.StateStopped, proto.StateRestarted, proto.StateReloaded:
	default:
		return nil, fmt.Errorf("invalid state %q", r.State)
	}
	return []proto.Op{{
		OpType: proto.OpTypeService,
		Service: &proto.ServiceOp{
			Unit:    r.Unit,
			State:   r.State,
			Enabled: r.Enabled,
		},
	}}, nil
}

// init registers the std.service compilers.
func init() {
	modules.Register("std.service.Unit", modules.CompilerFunc(compileUnit))
}
