// Package modules compiles playbook resources into primitive ops for the
// agent. Each module family provides a compiler keyed on the resource
// type; the agent only understands File, Command and Service ops, so new
// modules (pkg, cron, users…) add a compiler here and never touch the
// agent. File contents (including templates) are rendered server-side.
package modules

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/claymod/claymod/internal/playbook"
	"github.com/claymod/claymod/internal/proto"
)

// Compiler turns one playbook resource into primitive ops. A compiler may
// emit several ops (e.g. Script writes its file then runs it).
type Compiler interface {
	Compile(res playbook.Resource, ctx playbook.RenderContext) ([]proto.Op, error)
}

// CompilerFunc adapts a function to the Compiler interface.
type CompilerFunc func(res playbook.Resource, ctx playbook.RenderContext) ([]proto.Op, error)

// Compile implements Compiler.
func (f CompilerFunc) Compile(res playbook.Resource, ctx playbook.RenderContext) ([]proto.Op, error) {
	return f(res, ctx)
}

var (
	regMu    sync.RWMutex
	registry = map[string]Compiler{}
)

// Register installs a compiler for a resource type. It panics on
// duplicate registration — module names are a closed set at init time.
func Register(resourceType string, c Compiler) {
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := registry[resourceType]; dup {
		panic("modules: duplicate registration for " + resourceType)
	}
	registry[resourceType] = c
}

// Compile turns one resource into primitive ops using the compiler
// registered for its type.
func Compile(res playbook.Resource, ctx playbook.RenderContext) ([]proto.Op, error) {
	regMu.RLock()
	c, ok := registry[res.Type]
	regMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("modules: no compiler registered for resource type %q", res.Type)
	}
	ops, err := c.Compile(res, ctx)
	if err != nil {
		return nil, fmt.Errorf("modules: compile %s %q: %w", res.Type, res.Name, err)
	}
	if len(ops) == 0 {
		return nil, fmt.Errorf("modules: compiler for %s %q produced no ops", res.Type, res.Name)
	}
	return ops, nil
}

// CompileAll compiles every resource of a playbook, in plan order.
func CompileAll(pb *playbook.Playbook, plan *playbook.Plan, ctx playbook.RenderContext) ([]proto.Op, error) {
	byName := make(map[string]*playbook.Resource, len(pb.Resources))
	for k := range pb.Resources {
		byName[pb.Resources[k].Name] = &pb.Resources[k]
	}
	var ops []proto.Op
	for _, task := range plan.Tasks {
		res := byName[task.Name]
		if res == nil {
			return nil, fmt.Errorf("modules: planned task %q not found in playbook", task.Name)
		}
		compiled, err := Compile(*res, ctx)
		if err != nil {
			return nil, err
		}
		ops = append(ops, compiled...)
	}
	return ops, nil
}

// DecodeResource unmarshals the raw resource object into target.
func DecodeResource(res playbook.Resource, target any) error {
	if err := json.Unmarshal(res.Raw, target); err != nil {
		return fmt.Errorf("decode %s: %w", res.Type, err)
	}
	return nil
}
