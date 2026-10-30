package stdcron

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/claymod/claymod/internal/playbook"
	"github.com/claymod/claymod/internal/proto"
)

// fakeCrontab puts a crontab(1) fake on PATH, backed by a store file:
// `crontab -l` cats the store (exit 1 when absent, like the real one),
// `crontab -` and `crontab <file>` replace it.
func fakeCrontab(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	store := filepath.Join(t.TempDir(), "crontab")
	script := "#!/bin/sh\ncase \"$1\" in\n" +
		"  -l)\n" +
		"    if [ -f \"$FAKE_CRONTAB_STORE\" ]; then cat \"$FAKE_CRONTAB_STORE\"; exit 0; fi\n" +
		"    echo \"fake crontab: no crontab\" >&2; exit 1 ;;\n" +
		"  -)\n" +
		"    cat > \"$FAKE_CRONTAB_STORE\"; exit 0 ;;\n" +
		"  *)\n" +
		"    [ $# -eq 1 ] || { echo \"fake crontab: usage\" >&2; exit 2; }\n" +
		"    cat \"$1\" > \"$FAKE_CRONTAB_STORE\"; exit 0 ;;\n" +
		"esac\n"
	if err := os.WriteFile(filepath.Join(bin, "crontab"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_CRONTAB_STORE", store)
	return store
}

// runOp simulates the agent's guard ordering for one compiled op:
// onlyIf / unlessIf decide, then the shell runs.
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

func compile(t *testing.T, name, schedule, command, ensure string) *proto.CommandOp {
	t.Helper()
	raw, err := json.Marshal(EntryResource{
		Type: "std.cron.Entry", Name: name, Schedule: schedule, Command: command, Ensure: ensure,
	})
	if err != nil {
		t.Fatal(err)
	}
	res := playbook.Resource{Type: "std.cron.Entry", Name: name, Raw: raw}
	ops, err := compileEntry(res, playbook.RenderContext{Vars: map[string]string{}})
	if err != nil {
		t.Fatalf("compileEntry: %v", err)
	}
	return ops[0].Command
}

func readStore(t *testing.T, store string) string {
	t.Helper()
	data, err := os.ReadFile(store)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatal(err)
	}
	return string(data)
}

func TestCronEntryInstallAndIdempotence(t *testing.T) {
	store := fakeCrontab(t)

	// Fresh install (no crontab yet).
	op := compile(t, "backup", "0 3 * * *", "/usr/local/bin/backup.sh", "present")
	ran, out, code := runOp(t, op)
	if !ran || code != 0 {
		t.Fatalf("install: ran=%v code=%d output=%s", ran, code, out)
	}
	if got := readStore(t, store); got != "0 3 * * * /usr/local/bin/backup.sh # claymod:backup\n" {
		t.Fatalf("store = %q", got)
	}

	// Second run: the guard matches the exact entry, op skipped.
	if ran, out, _ := runOp(t, op); ran {
		t.Fatalf("second run not skipped: %s", out)
	}

	// Update: same marker, different command → replaced, not duplicated.
	op2 := compile(t, "backup", "30 4 * * *", "/usr/local/bin/backup2.sh", "present")
	if ran, out, code := runOp(t, op2); !ran || code != 0 {
		t.Fatalf("update: ran=%v code=%d output=%s", ran, code, out)
	}
	if got := readStore(t, store); strings.Count(got, "# claymod:backup") != 1 ||
		!strings.Contains(got, "30 4 * * * /usr/local/bin/backup2.sh # claymod:backup") {
		t.Fatalf("store after update = %q", got)
	}
}

func TestCronEntryAbsentRemovesOnlyMarkedLines(t *testing.T) {
	store := fakeCrontab(t)
	if err := os.WriteFile(store, []byte(
		"*/5 * * * * /usr/bin/other\n"+
			"0 3 * * * /usr/local/bin/old.sh # claymod:stale\n"+
			"0 4 * * * /usr/bin/mine # claymod:mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	op := compile(t, "stale", "@daily", "/usr/local/bin/old.sh", "absent")
	ran, out, code := runOp(t, op)
	if !ran || code != 0 {
		t.Fatalf("remove: ran=%v code=%d output=%s", ran, code, out)
	}
	want := "*/5 * * * * /usr/bin/other\n0 4 * * * /usr/bin/mine # claymod:mine\n"
	if got := readStore(t, store); got != want {
		t.Fatalf("store = %q, want %q", got, want)
	}

	// Second run: only_if fails (no marked line), op skipped.
	if ran, out, _ := runOp(t, op); ran {
		t.Fatalf("second absent run not skipped: %s", out)
	}
}

// TestCronEntryMarkerIsEndAnchored pins the prefix-collision fix: a
// resource named "backup" must not touch "backup-daily"'s entry.
func TestCronEntryMarkerIsEndAnchored(t *testing.T) {
	store := fakeCrontab(t)
	if err := os.WriteFile(store, []byte(
		"0 3 * * * /usr/local/bin/daily.sh # claymod:backup-daily\n"+
			"0 2 * * * /usr/local/bin/hourly.sh # claymod:backup\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	op := compile(t, "backup", "0 2 * * *", "/usr/local/bin/hourly.sh", "absent")
	ran, out, code := runOp(t, op)
	if !ran || code != 0 {
		t.Fatalf("absent: ran=%v code=%d output=%s", ran, code, out)
	}
	got := readStore(t, store)
	if !strings.Contains(got, "# claymod:backup-daily") {
		t.Errorf("prefix collision: backup-daily's entry was removed:\n%s", got)
	}
	if strings.Contains(got, "# claymod:backup\n") {
		t.Errorf("own entry not removed:\n%s", got)
	}
}

// TestCronEntryNameWithQuote pins the quoting fix: a name containing a
// single quote must not break the recipes or execute anything.
func TestCronEntryNameWithQuote(t *testing.T) {
	store := fakeCrontab(t)

	op := compile(t, "nightly's", "0 3 * * *", "/usr/local/bin/backup.sh", "present")
	ran, out, code := runOp(t, op)
	if !ran || code != 0 {
		t.Fatalf("install: ran=%v code=%d output=%s", ran, code, out)
	}
	if got := readStore(t, store); got != "0 3 * * * /usr/local/bin/backup.sh # claymod:nightly's\n" {
		t.Fatalf("store = %q", got)
	}

	// The guard matches, so a second run is skipped (the quote must not
	// break the guard either).
	if ran, out, _ := runOp(t, op); ran {
		t.Fatalf("second run not skipped: %s", out)
	}

	// Absent with the same quoted name removes exactly the entry.
	opAbsent := compile(t, "nightly's", "0 3 * * *", "/usr/local/bin/backup.sh", "absent")
	if ran, out, code := runOp(t, opAbsent); !ran || code != 0 {
		t.Fatalf("remove: ran=%v code=%d output=%s", ran, code, out)
	}
	if got := readStore(t, store); got != "" {
		t.Fatalf("store after remove = %q, want empty", got)
	}
}

func TestCronEntryQuotesCommand(t *testing.T) {
	store := fakeCrontab(t)
	op := compile(t, "tricky", "0 3 * * *", `/usr/bin/run --msg "it's $(date)" ; echo done`, "present")
	if ran, out, code := runOp(t, op); !ran || code != 0 {
		t.Fatalf("install: ran=%v code=%d output=%s", ran, code, out)
	}
	want := "0 3 * * * /usr/bin/run --msg \"it's $(date)\" ; echo done # claymod:tricky\n"
	if got := readStore(t, store); got != want {
		t.Fatalf("store = %q, want %q (the command must be stored literally)", got, want)
	}
}
