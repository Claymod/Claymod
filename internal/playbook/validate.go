package playbook

import (
	"fmt"
	"sort"
	"strings"
)

// Validate checks the playbook for structural errors: missing names,
// duplicate names, unknown resource types and dangling dependencies.
// Cycle detection is done by the planner (topological order).
func (pb *Playbook) Validate() error {
	if len(pb.Resources) == 0 {
		return fmt.Errorf("playbook: no resources defined")
	}
	byName := make(map[string]*Resource, len(pb.Resources))
	for k := range pb.Resources {
		res := &pb.Resources[k]
		if res.Name == "" {
			return fmt.Errorf("playbook: resource #%d has no name", k)
		}
		if res.Type == "" {
			return fmt.Errorf("playbook: resource %q has no type", res.Name)
		}
		if !KnownType(res.Type) {
			return fmt.Errorf("playbook: resource %q has unknown type %q (known: %s)",
				res.Name, res.Type, strings.Join(KnownTypes(), ", "))
		}
		if _, dup := byName[res.Name]; dup {
			return fmt.Errorf("playbook: duplicate resource name %q", res.Name)
		}
		byName[res.Name] = res
	}
	for k := range pb.Resources {
		res := &pb.Resources[k]
		for _, dep := range res.DependsOn {
			if _, ok := byName[dep]; !ok {
				return fmt.Errorf("playbook: resource %q depends on unknown resource %q", res.Name, dep)
			}
			if dep == res.Name {
				return fmt.Errorf("playbook: resource %q depends on itself", res.Name)
			}
		}
	}
	// Cycles make the playbook unplannable: detect them here so plain
	// `playbook validate` reports them too, with the cycle path.
	if _, err := topologicalOrder(pb.Resources); err != nil {
		return err
	}
	return nil
}

// knownTypes lists the resource types the schema v1 produces. Modules
// (Phase 5) compile these to primitive ops.
var knownTypes = map[string]bool{
	"std.files.Copy":      true,
	"std.files.Template":  true,
	"std.files.Directory": true,
	"std.commands.Shell":  true,
	"std.commands.Script": true,
	"std.service.Unit":    true,
}

// KnownType reports whether the resource type is supported.
func KnownType(t string) bool { return knownTypes[t] }

// KnownTypes returns the supported resource types, sorted.
func KnownTypes() []string {
	out := make([]string, 0, len(knownTypes))
	for t := range knownTypes {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
