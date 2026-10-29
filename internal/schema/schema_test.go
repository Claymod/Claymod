package schema

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	pklschema "github.com/claymod/claymod/pkl"
)

// withCacheRoot points the materialization cache at a temp dir and
// clears CLAYMOD_SCHEMA_DIR so StdDir exercises the embedded path.
func withCacheRoot(t *testing.T) string {
	t.Helper()
	t.Setenv("CLAYMOD_SCHEMA_DIR", "")
	root := t.TempDir()
	userCacheDir = func() (string, error) { return root, nil }
	t.Cleanup(func() { userCacheDir = os.UserCacheDir })
	return root
}

func TestStdDirEmbedded(t *testing.T) {
	root := withCacheRoot(t)

	first, err := StdDir()
	if err != nil {
		t.Fatalf("StdDir: %v", err)
	}
	if !filepath.IsAbs(first) {
		t.Errorf("StdDir = %q, want absolute", first)
	}
	wantPrefix := filepath.Join(root, "claymod", "schema")
	if !strings.HasPrefix(first, wantPrefix) {
		t.Errorf("StdDir = %q, want under %s", first, wantPrefix)
	}

	// The materialized std must match the embedded source of truth.
	base, err := os.ReadFile(filepath.Join(first, "claymod", "base.pkl"))
	if err != nil {
		t.Fatalf("read materialized base.pkl: %v", err)
	}
	embedded, err := pklschema.FS.ReadFile("claymod/base.pkl")
	if err != nil {
		t.Fatalf("read embedded base.pkl: %v", err)
	}
	if string(base) != string(embedded) {
		t.Error("materialized base.pkl differs from the embedded schema")
	}

	// Second call reuses the dir as-is (no rewrite).
	sentinel := filepath.Join(first, "sentinel")
	if err := os.WriteFile(sentinel, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := StdDir()
	if err != nil {
		t.Fatalf("second StdDir: %v", err)
	}
	if second != first {
		t.Errorf("StdDir changed between calls: %q then %q", first, second)
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Error("second StdDir rewrote the schema cache dir")
	}
}

func TestStdDirEnvOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CLAYMOD_SCHEMA_DIR", dir)
	got, err := StdDir()
	if err != nil {
		t.Fatalf("StdDir: %v", err)
	}
	if abs, _ := filepath.Abs(dir); got != abs {
		t.Errorf("StdDir = %q, want %q", got, abs)
	}

	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAYMOD_SCHEMA_DIR", file)
	if _, err := StdDir(); err == nil {
		t.Error("StdDir accepted a file as CLAYMOD_SCHEMA_DIR")
	}
	t.Setenv("CLAYMOD_SCHEMA_DIR", filepath.Join(t.TempDir(), "missing"))
	if _, err := StdDir(); err == nil {
		t.Error("StdDir accepted a missing CLAYMOD_SCHEMA_DIR")
	}
}

func TestModulePath(t *testing.T) {
	t.Setenv("CLAYMOD_SCHEMA_DIR", "")
	withCacheRoot(t)

	std, err := StdDir()
	if err != nil {
		t.Fatal(err)
	}
	// Relative, duplicate and empty entries collapse; std always first.
	got, err := ModulePath("/pb/playbook.pkl", []string{"rel", "", std, "rel"})
	if err != nil {
		t.Fatalf("ModulePath: %v", err)
	}
	if len(got) != 2 || got[0] != std || !filepath.IsAbs(got[1]) {
		t.Errorf("ModulePath = %v, want [%s <abs rel>]", got, std)
	}
}

func TestExtraFromEnv(t *testing.T) {
	t.Setenv("CLAYMOD_MODULE_PATH", "")
	if got := ExtraFromEnv(); got != nil {
		t.Errorf("ExtraFromEnv with unset env = %v, want nil", got)
	}
	t.Setenv("CLAYMOD_MODULE_PATH", "/a:/b")
	got := ExtraFromEnv()
	if len(got) != 2 || got[0] != "/a" || got[1] != "/b" {
		t.Errorf("ExtraFromEnv = %v, want [/a /b]", got)
	}
}
