package pkl

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// requirePkl skips the test when the pkl CLI is not installed.
func requirePkl(t *testing.T) *Evaluator {
	t.Helper()
	ev := New()
	if !ev.Available() {
		t.Skip("pkl CLI not installed; run scripts/bootstrap-pkl.sh (see make test-full)")
	}
	return ev
}

func TestMissingBinaryReturnsErrPklNotFound(t *testing.T) {
	ev := &Evaluator{PklBinary: "definitely-not-pkl-binary"}
	if ev.Available() {
		t.Fatal("Available reported true for a missing binary")
	}
	_, err := ev.Evaluate(context.Background(), "x.pkl", EvalOptions{})
	if err == nil || !strings.Contains(err.Error(), "bootstrap-pkl.sh") {
		t.Fatalf("error = %v, want ErrPklNotFound with bootstrap hint", err)
	}
}

func TestVersion(t *testing.T) {
	ev := requirePkl(t)
	v, err := ev.Version()
	if err != nil {
		t.Fatalf("Version returned error: %v", err)
	}
	if !strings.Contains(v, "Pkl") {
		t.Errorf("version = %q, want Pkl prefix", v)
	}
}

func TestEvaluateToJSON(t *testing.T) {
	ev := requirePkl(t)
	dir := t.TempDir()
	module := filepath.Join(dir, "doc.pkl")
	if err := os.WriteFile(module, []byte(`answer = 42
greeting = "hello"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Answer   int    `json:"answer"`
		Greeting string `json:"greeting"`
	}
	err := ev.EvaluateTo(context.Background(), module, EvalOptions{}, &doc)
	if err != nil {
		t.Fatalf("EvaluateTo returned error: %v", err)
	}
	if doc.Answer != 42 || doc.Greeting != "hello" {
		t.Errorf("doc = %+v", doc)
	}
}

func TestEvaluateWithEnvVars(t *testing.T) {
	ev := requirePkl(t)
	dir := t.TempDir()
	module := filepath.Join(dir, "doc.pkl")
	// read? + ?? is the documented optional-env pattern.
	if err := os.WriteFile(module, []byte(`host = read?("env:CLAYMOD_TEST_HOST") ?? "unset"
`), 0o644); err != nil {
		t.Fatal(err)
	}

	var doc struct {
		Host string `json:"host"`
	}
	err := ev.EvaluateTo(context.Background(), module, EvalOptions{
		Env: map[string]string{"CLAYMOD_TEST_HOST": "web01"},
	}, &doc)
	if err != nil {
		t.Fatalf("EvaluateTo returned error: %v", err)
	}
	if doc.Host != "web01" {
		t.Errorf("host = %q, want web01 (env not injected)", doc.Host)
	}

	// Parent process env must NOT be touched.
	if os.Getenv("CLAYMOD_TEST_HOST") != "" {
		t.Error("evaluation mutated the parent process environment")
	}
}

func TestEvaluateWithProperties(t *testing.T) {
	ev := requirePkl(t)
	dir := t.TempDir()
	module := filepath.Join(dir, "doc.pkl")
	if err := os.WriteFile(module, []byte(`val = read?("prop:claymod.test") ?? "unset"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Val string `json:"val"`
	}
	err := ev.EvaluateTo(context.Background(), module, EvalOptions{
		Properties: map[string]string{"claymod.test": "propvalue"},
	}, &doc)
	if err != nil {
		t.Fatalf("EvaluateTo returned error: %v", err)
	}
	if doc.Val != "propvalue" {
		t.Errorf("val = %q, want propvalue", doc.Val)
	}
}

func TestEvaluateWithModulePath(t *testing.T) {
	ev := requirePkl(t)
	dir := t.TempDir()
	// modulepath:/base.pkl must resolve via ModulePath. An amending
	// module may only amend existing properties (PKL rule), so base
	// declares both fields and user.pkl overrides one of them.
	if err := os.WriteFile(filepath.Join(dir, "base.pkl"), []byte(`x = 1
w = 0
`), 0o644); err != nil {
		t.Fatal(err)
	}
	module := filepath.Join(dir, "user.pkl")
	if err := os.WriteFile(module, []byte(`amends "modulepath:/base.pkl"
w = 7
`), 0o644); err != nil {
		t.Fatal(err)
	}
	raw, err := ev.Evaluate(context.Background(), module, EvalOptions{ModulePath: []string{dir}})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	var doc struct {
		X int `json:"x"`
		W int `json:"w"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.X != 1 || doc.W != 7 {
		t.Errorf("doc = %+v, want x=1 (from base) w=7 (amended)", doc)
	}
}

func TestEvaluateErrorCarriesPklDiagnostics(t *testing.T) {
	ev := requirePkl(t)
	dir := t.TempDir()
	module := filepath.Join(dir, "broken.pkl")
	// A type error must surface pkl's own message.
	if err := os.WriteFile(module, []byte(`x: Int = "not an int"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := ev.Evaluate(context.Background(), module, EvalOptions{})
	if err == nil {
		t.Fatal("Evaluate accepted a broken module")
	}
	if !strings.Contains(err.Error(), "pkl:") {
		t.Errorf("error = %q, want pkl diagnostics", err.Error())
	}
}

func TestEvaluateTimeout(t *testing.T) {
	ev := requirePkl(t)
	dir := t.TempDir()
	module := filepath.Join(dir, "slow.pkl")
	// A module that loops: bounded by the evaluator timeout, not ours.
	if err := os.WriteFile(module, []byte(`import "pkl:eval"
f(x) = if (x == 0) 0 else f(x - 1)
x = f(100)
`), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := ev.Evaluate(ctx, module, EvalOptions{Timeout: time.Millisecond})
	if err == nil {
		t.Fatal("Evaluate completed despite a 1ms timeout")
	}
}
