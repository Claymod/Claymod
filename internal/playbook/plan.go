package playbook

import (
	"fmt"
)

// topologicalOrder returns the resources in dependency order: every
// resource appears after all of its dependencies. The order is stable —
// resources with no ordering constraint keep their declaration order.
// Dependency cycles are detected and reported with the cycle path.
func topologicalOrder(resources []Resource) ([]Resource, error) {
	byName := make(map[string]*Resource, len(resources))
	for k := range resources {
		byName[resources[k].Name] = &resources[k]
	}

	const (
		white = 0 // unvisited
		gray  = 1 // on the current DFS path
		black = 2 // done
	)
	state := make(map[string]int, len(resources))
	var out []Resource
	var path []string

	var visit func(res *Resource) error
	visit = func(res *Resource) error {
		switch state[res.Name] {
		case gray:
			return cycleError(path, res.Name)
		case black:
			return nil
		}
		state[res.Name] = gray
		path = append(path, res.Name)
		for _, dep := range res.DependsOn {
			depRes, ok := byName[dep]
			if !ok {
				return fmt.Errorf("playbook: resource %q depends on unknown resource %q", res.Name, dep)
			}
			if err := visit(depRes); err != nil {
				return err
			}
		}
		path = path[:len(path)-1]
		state[res.Name] = black
		out = append(out, *res)
		return nil
	}

	for k := range resources {
		if err := visit(&resources[k]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// cycleError renders the dependency cycle path for a clear error message.
func cycleError(path []string, target string) error {
	// Trim the path down to the cycle: from the first occurrence of
	// target to the end, then close the loop with target again.
	start := 0
	for k, name := range path {
		if name == target {
			start = k
			break
		}
	}
	cycle := append(append([]string{}, path[start:]...), target)
	return fmt.Errorf("playbook: dependency cycle detected: %s", joinArrow(cycle))
}

// joinArrow renders ["a"; "b"; "c"] as "a -> b -> c".
func joinArrow(names []string) string {
	out := ""
	for k, name := range names {
		if k > 0 {
			out += " -> "
		}
		out += name
	}
	return out
}
