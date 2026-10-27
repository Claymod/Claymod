package playbook

import (
	"encoding/json"
	"strings"
	"testing"
)

const sampleDoc = `{
  "hostName": "",
  "hosts": ["web01", "web02"],
  "vars": {"environment": "production"},
  "resources": [
    {"type": "std.files.Copy", "name": "motd", "dependsOn": [], "source": "files/motd.txt", "dest": "/etc/motd", "mode": "0644"},
    {"type": "std.service.Unit", "name": "nginx", "dependsOn": ["motd"], "unit": "nginx", "state": "started"},
    {"type": "std.files.Directory", "name": "logdir", "dependsOn": ["nginx"], "path": "/var/log/app"}
  ]
}`

func TestParseAndPlan(t *testing.T) {
	pb, err := Parse([]byte(sampleDoc))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if pb.HostName != "" || len(pb.Hosts) != 2 || pb.Vars["environment"] != "production" {
		t.Errorf("parsed playbook wrong: %+v", pb)
	}
	plan, err := pb.Plan("web01")
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	if plan.Host != "web01" {
		t.Errorf("plan host = %q", plan.Host)
	}
	// Dependency order: motd -> nginx -> logdir, even though the last two
	// are listed in dependency order here, the planner must not depend on
	// declaration order.
	want := []string{"motd", "nginx", "logdir"}
	for k, name := range want {
		if plan.Tasks[k].Name != name {
			t.Errorf("task %d = %q, want %q", k, plan.Tasks[k].Name, name)
		}
	}
	if plan.Tasks[2].DependsOn[0] != "nginx" {
		t.Errorf("logdir deps = %v", plan.Tasks[2].DependsOn)
	}
}

func TestPlanTopologicalOrder(t *testing.T) {
	// Declared out of order on purpose: dep last, root first would be
	// wrong; the planner must reorder.
	doc := `{"resources": [
		{"type": "std.service.Unit", "name": "svc", "dependsOn": ["conf"], "unit": "nginx"},
		{"type": "std.files.Copy", "name": "conf", "dependsOn": ["dir"], "source": "a", "dest": "/etc/a"},
		{"type": "std.files.Directory", "name": "dir", "dependsOn": [], "path": "/etc/dir"}
	]}`
	pb, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := pb.Plan("")
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	got := []string{plan.Tasks[0].Name, plan.Tasks[1].Name, plan.Tasks[2].Name}
	want := []string{"dir", "conf", "svc"}
	for k := range want {
		if got[k] != want[k] {
			t.Fatalf("plan order = %v, want %v", got, want)
		}
	}
}

func TestPlanGoldenJSON(t *testing.T) {
	pb, err := Parse([]byte(sampleDoc))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := pb.Plan("web01")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	// Golden: stable JSON with dep order, empty deps as [] not null.
	want := `{"host":"web01","hosts":["web01","web02"],"vars":{"environment":"production"},` +
		`"tasks":[{"index":0,"name":"motd","type":"std.files.Copy","dependsOn":[]},` +
		`{"index":1,"name":"nginx","type":"std.service.Unit","dependsOn":["motd"]},` +
		`{"index":2,"name":"logdir","type":"std.files.Directory","dependsOn":["nginx"]}]}`
	if string(raw) != want {
		t.Errorf("plan JSON mismatch:\n got: %s\nwant: %s", raw, want)
	}
}

func TestValidateErrors(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{
			name: "no resources",
			doc:  `{"resources": []}`,
			want: "no resources",
		},
		{
			name: "missing name",
			doc:  `{"resources": [{"type": "std.files.Copy", "source": "a", "dest": "/a"}]}`,
			want: "has no name",
		},
		{
			name: "missing type",
			doc:  `{"resources": [{"name": "x", "source": "a", "dest": "/a"}]}`,
			want: "has no type",
		},
		{
			name: "unknown type",
			doc:  `{"resources": [{"type": "std.bogus.Thing", "name": "x"}]}`,
			want: "unknown type",
		},
		{
			name: "duplicate name",
			doc:  `{"resources": [{"type": "std.files.Copy", "name": "x"}, {"type": "std.files.Copy", "name": "x"}]}`,
			want: "duplicate resource name",
		},
		{
			name: "dangling dep",
			doc:  `{"resources": [{"type": "std.files.Copy", "name": "x", "dependsOn": ["ghost"]}]}`,
			want: "unknown resource",
		},
		{
			name: "self dep",
			doc:  `{"resources": [{"type": "std.files.Copy", "name": "x", "dependsOn": ["x"]}]}`,
			want: "depends on itself",
		},
		{
			name: "cycle",
			doc: `{"resources": [
				{"type": "std.files.Copy", "name": "a", "dependsOn": ["b"]},
				{"type": "std.files.Copy", "name": "b", "dependsOn": ["a"]}
			]}`,
			want: "dependency cycle",
		},
		{
			name: "three-node cycle",
			doc: `{"resources": [
				{"type": "std.files.Copy", "name": "a", "dependsOn": ["c"]},
				{"type": "std.files.Copy", "name": "b", "dependsOn": ["a"]},
				{"type": "std.files.Copy", "name": "c", "dependsOn": ["b"]}
			]}`,
			want: "dependency cycle",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pb, err := Parse([]byte(tc.doc))
			if err != nil {
				t.Fatalf("Parse returned error: %v", err)
			}
			_, err = pb.Plan("")
			if err == nil {
				t.Fatalf("Plan accepted bad playbook: %s", tc.doc)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

func TestCycleErrorNamesPath(t *testing.T) {
	doc := `{"resources": [
		{"type": "std.files.Copy", "name": "a", "dependsOn": ["b"]},
		{"type": "std.files.Copy", "name": "b", "dependsOn": ["c"]},
		{"type": "std.files.Copy", "name": "c", "dependsOn": ["a"]}
	]}`
	pb, _ := Parse([]byte(doc))
	_, err := pb.Plan("")
	if err == nil {
		t.Fatal("Plan accepted a cycle")
	}
	if !strings.Contains(err.Error(), "a -> b -> c -> a") {
		t.Errorf("cycle error = %q, want path a -> b -> c -> a", err.Error())
	}
}

func TestPlanEmptyHostsAndVars(t *testing.T) {
	doc := `{"resources": [{"type": "std.files.Copy", "name": "x", "source": "a", "dest": "/a"}]}`
	pb, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := pb.Plan("")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Vars == nil || len(plan.Vars) != 0 {
		t.Errorf("vars = %v, want empty map", plan.Vars)
	}
	if plan.Hosts == nil || len(plan.Hosts) != 0 {
		t.Errorf("hosts = %v, want empty slice", plan.Hosts)
	}
	raw, err := json.Marshal(plan.Tasks[0].DependsOn)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "[]" {
		t.Errorf("dependsOn JSON = %s, want [] (not null)", raw)
	}
}
