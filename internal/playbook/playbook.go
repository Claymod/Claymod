// Package playbook turns evaluated PKL playbooks into validated,
// dependency-ordered plans. The control server runs this pipeline:
// pkl eval -> JSON -> parse -> validate -> topological plan.
package playbook

import (
	"encoding/json"
	"fmt"
)

// Playbook is the evaluated document of a claymod PKL playbook.
type Playbook struct {
	// HostName is the host being rendered for ("" for standalone
	// validate/plan runs).
	HostName string `json:"hostName"`
	// Hosts selects the hosts this playbook applies to.
	Hosts []string `json:"hosts"`
	// Vars are per-host variables passed to template rendering.
	Vars map[string]string `json:"vars"`
	// Resources are the declarative items to apply.
	Resources []Resource `json:"resources"`
}

// Resource is one playbook item. Type-specific fields stay in Raw so the
// module compilers (Phase 5) can decode them without the planner knowing
// every shape.
type Resource struct {
	// Type is the module discriminator (e.g. "std.files.Copy").
	Type string `json:"type"`
	// Name is unique within the playbook; dependsOn refers to it.
	Name string `json:"name"`
	// DependsOn lists resource names that must be planned first.
	DependsOn []string `json:"dependsOn"`
	// Raw is the full decoded object, retained for compilers.
	Raw json.RawMessage `json:"-"`
}

// UnmarshalJSON captures the full object (for Raw) alongside the common
// fields.
func (r *Resource) UnmarshalJSON(data []byte) error {
	type common struct {
		Type      string   `json:"type"`
		Name      string   `json:"name"`
		DependsOn []string `json:"dependsOn"`
	}
	var c common
	if err := json.Unmarshal(data, &c); err != nil {
		return err
	}
	r.Type = c.Type
	r.Name = c.Name
	r.DependsOn = c.DependsOn
	r.Raw = append(r.Raw[:0], data...)
	return nil
}

// Parse decodes an evaluated playbook document.
func Parse(doc []byte) (*Playbook, error) {
	var pb Playbook
	if err := json.Unmarshal(doc, &pb); err != nil {
		return nil, fmt.Errorf("playbook: decode: %w", err)
	}
	return &pb, nil
}

// Task is one planned step: a resource in execution order.
type Task struct {
	Index     int      `json:"index"`
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	DependsOn []string `json:"dependsOn"`
}

// Plan is the execution plan for one host: tasks in dependency order.
type Plan struct {
	Host  string            `json:"host"`
	Hosts []string          `json:"hosts"`
	Vars  map[string]string `json:"vars"`
	Tasks []Task            `json:"tasks"`
}

// Plan validates the playbook and returns the per-host execution plan,
// with tasks in a stable topological order.
func (pb *Playbook) Plan(host string) (*Plan, error) {
	if err := pb.Validate(); err != nil {
		return nil, err
	}
	order, err := topologicalOrder(pb.Resources)
	if err != nil {
		return nil, err
	}
	tasks := make([]Task, len(order))
	for k, res := range order {
		deps := res.DependsOn
		if deps == nil {
			deps = []string{}
		}
		tasks[k] = Task{
			Index:     k,
			Name:      res.Name,
			Type:      res.Type,
			DependsOn: deps,
		}
	}
	vars := pb.Vars
	if vars == nil {
		vars = map[string]string{}
	}
	hosts := pb.Hosts
	if hosts == nil {
		hosts = []string{}
	}
	return &Plan{
		Host:  host,
		Hosts: hosts,
		Vars:  vars,
		Tasks: tasks,
	}, nil
}
