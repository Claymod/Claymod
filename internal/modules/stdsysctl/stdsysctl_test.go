package stdsysctl

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/claymod/claymod/internal/playbook"
	"github.com/claymod/claymod/internal/proto"
)

// fakeSysctl puts a sysctl(8) fake on PATH: `sysctl -n key` reads the
// store, `sysctl key=value` writes it (the two forms the recipe uses).
func fakeSysctl(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	store := filepath.Join(t.TempDir(), "sysctl")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = \"-n\" ]; then\n" +
		"  [ -f \"$FAKE_SYSCTL_STORE\" ] || { echo \"fake sysctl: unknown key $2\" >&2; exit 1; }\n" +
		"  v=$(grep \"^$2=\" \"$FAKE_SYSCTL_STORE\" | tail -n 1 | cut -d= -f2-)\n" +
		"  [ -n \"$v\" ] && { printf '%s\\n' \"$v\"; exit 0; }\n" +
		"  echo \"fake sysctl: unknown key $2\" >&2; exit 1\n" +
		"fi\n" +
		"for arg in \"$@\"; do\n" +
		"  case \"$arg\" in\n" +
		"    *=*)\n" +
		"      k=${arg%%=*}; v=${arg#*=}\n" +
		"      if [ -f \"$FAKE_SYSCTL_STORE\" ]; then\n" +
		"        grep -v \"^$k=\" \"$FAKE_SYSCTL_STORE\" > \"$FAKE_SYSCTL_STORE.tmp\" || true\n" +
		"        mv \"$FAKE_SYSCTL_STORE.tmp\" \"$FAKE_SYSCTL_STORE\"\n" +
		"      fi\n" +
		"      printf '%s=%s\\n' \"$k\" \"$v\" >> \"$FAKE_SYSCTL_STORE\"\n" +
		"      exit 0 ;;\n" +
		"  esac\n" +
		"done\n" +
		"echo \"fake sysctl: unsupported args: $*\" >&2; exit 2\n"
	if err := os.WriteFile(filepath.Join(bin, "sysctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_SYSCTL_STORE", store)
	return store
}

// runOp simulates the agent's guard ordering for one compiled op.
func runOp(t *testing.T, cmd *proto.CommandOp) (ran bool, output string, errCode int) {
	t.Helper()
	guard := func(g string) bool {
		c := exec.Command("/bin/sh", "-c", g)
		return c.Run() == nil
	}
	if cmd.OnlyIf != "" && !guard(cmd.OnlyIf) {
		return false, "skipped: only_if", 0
	}
	if cmd.UnlessIf != "" && guard(cmd.UnlessIf) {
		return false, "skipped: unless_if", 0
	}
	c := exec.Command("/bin/sh", "-c", cmd.Shell)
	out, err := c.CombinedOutput()
	if err != nil {
		return true, string(out), c.ProcessState.ExitCode()
	}
	return true, string(out), 0
}

func compile(t *testing.T, key, value string) *proto.CommandOp {
	t.Helper()
	raw, err := json.Marshal(SysctlResource{Type: "std.sysctl.Sysctl", Name: "x", Key: key, Value: value})
	if err != nil {
		t.Fatal(err)
	}
	res := playbook.Resource{Type: "std.sysctl.Sysctl", Name: "x", Raw: raw}
	ops, err := compileSysctl(res, playbook.RenderContext{Vars: map[string]string{}})
	if err != nil {
		t.Fatalf("compileSysctl: %v", err)
	}
	return ops[0].Command
}

func TestSysctlSetAndIdempotence(t *testing.T) {
	store := fakeSysctl(t)

	// Set on an unknown key.
	op := compile(t, "net.ipv4.ip_forward", "1")
	ran, out, code := runOp(t, op)
	if !ran || code != 0 {
		t.Fatalf("set: ran=%v code=%d output=%s", ran, code, out)
	}
	if got, err := os.ReadFile(store); err != nil || string(got) != "net.ipv4.ip_forward=1\n" {
		t.Fatalf("store = %q, err %v", got, err)
	}

	// Second run: guard sees the value, op skipped.
	if ran, out, _ := runOp(t, op); ran {
		t.Fatalf("second run not skipped: %s", out)
	}

	// Change the value: guard sees the old one, op updates.
	op2 := compile(t, "net.ipv4.ip_forward", "0")
	if ran, out, code := runOp(t, op2); !ran || code != 0 {
		t.Fatalf("update: ran=%v code=%d output=%s", ran, code, out)
	}
	if got, err := os.ReadFile(store); err != nil || string(got) != "net.ipv4.ip_forward=0\n" {
		t.Fatalf("store after update = %q, err %v", got, err)
	}
}

// TestSysctlWriteFormIsUnquotedEqual pins the cross-implementation form:
// the recipe writes `sysctl 'key'='value'` — after sh dequoting the
// binary receives key=value, the form procps, busybox and BSD all parse
// as a write (verified 2026-10-30 on macOS, alpine, debian).
func TestSysctlWriteFormIsUnquotedEqual(t *testing.T) {
	op := compile(t, "kernel.hostname", "host7")
	if op.Shell != `sysctl 'kernel.hostname'='host7'` {
		t.Errorf("shell = %q, want sysctl 'kernel.hostname'='host7'", op.Shell)
	}
}
