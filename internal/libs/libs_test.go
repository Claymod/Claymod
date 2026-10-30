package libs

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// withCacheRoot isolates the library cache (and the schema cache) in a
// temp dir via the CLAYMOD_CACHE_DIR override.
func withCacheRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("CLAYMOD_CACHE_DIR", root)
	return root
}

func requireGitCLI(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git CLI not installed")
	}
}

// fixtureLibRepo creates a git repo with one pkl module under pkl/acme/,
// commits it, tags v1.0.0, adds a second commit on main and tags v1.1.0.
// Returns the repo dir and both commits.
func fixtureLibRepo(t *testing.T) (dir, commit1, commit2 string) {
	t.Helper()
	requireGitCLI(t)
	dir = filepath.Join(t.TempDir(), "acme-lib")
	if err := os.MkdirAll(filepath.Join(dir, "pkl", "acme"), 0o755); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) string {
		full := append([]string{"-c", "user.email=t@t", "-c", "user.name=t", "-C", dir}, args...)
		out, err := exec.Command("git", full...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	// The branch name must not depend on ambient git config (CI runners
	// default to master): the branch-tracking test pins main.
	git("-c", "init.defaultBranch=main", "init", "--quiet")
	write := func(content string) {
		if err := os.WriteFile(filepath.Join(dir, "pkl", "acme", "baseline.pkl"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("module acme.baseline\n\nmotd = \"acme v1\"\n")
	git("add", "-A")
	git("commit", "--quiet", "-m", "v1")
	commit1 = git("rev-parse", "HEAD")
	git("tag", "v1.0.0")
	write("module acme.baseline\n\nmotd = \"acme v2\"\n")
	git("add", "-A")
	git("commit", "--quiet", "-m", "v2")
	commit2 = git("rev-parse", "HEAD")
	git("tag", "v1.1.0")
	return dir, commit1, commit2
}

// writeProject writes a claymod.project.yaml and returns its path.
func writeProject(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ProjectFileName)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDiscoverWalksUp(t *testing.T) {
	withCacheRoot(t)
	projectPath := writeProject(t, "version: 1\nlibraries:\n  - name: acme\n    path: ./lib\n")
	proj, err := Load(projectPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// From the project dir itself and from a nested subdir.
	for _, sub := range []string{proj.Dir, filepath.Join(proj.Dir, "playbooks", "nested")} {
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		got, err := Discover(sub)
		if err != nil {
			t.Fatalf("Discover(%s): %v", sub, err)
		}
		if got == nil || got.Dir != proj.Dir {
			t.Errorf("Discover(%s) = %v, want project at %s", sub, got, proj.Dir)
		}
	}

	// No project anywhere: nil, no error.
	empty := t.TempDir()
	got, err := Discover(empty)
	if err != nil || got != nil {
		t.Errorf("Discover(empty) = %v, %v; want nil, nil", got, err)
	}
}

func TestLoadRejectsBadProjects(t *testing.T) {
	withCacheRoot(t)
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"duplicate names", "version: 1\nlibraries:\n  - name: a\n    path: ./x\n  - name: a\n    path: ./y\n", "duplicate name"},
		{"reserved name", "version: 1\nlibraries:\n  - name: claymod\n    path: ./x\n", "reserved"},
		{"git without ref", "version: 1\nlibraries:\n  - name: a\n    git: /tmp/repo\n", "ref is required"},
		{"no source", "version: 1\nlibraries:\n  - name: a\n", "needs git"},
		{"bad version", "version: 2\nlibraries: []\n", "unsupported project version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeProject(t, tc.content)
			_, err := Load(path)
			if err == nil {
				t.Fatalf("Load accepted bad project:\n%s", tc.content)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

func TestSyncLocalLibrary(t *testing.T) {
	withCacheRoot(t)
	projectPath := writeProject(t, "version: 1\nlibraries:\n  - name: acme\n    path: ./lib\n")
	proj, err := Load(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	libDir := filepath.Join(proj.Dir, "lib")
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatal(err)
	}

	dirs, err := proj.Sync(false)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(dirs) != 1 || dirs[0] != libDir {
		t.Errorf("Sync = %v, want [%s]", dirs, libDir)
	}

	// A missing local dir is a clear error.
	broken := writeProject(t, "version: 1\nlibraries:\n  - name: acme\n    path: ./ghost\n")
	proj2, err := Load(broken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proj2.Sync(false); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("Sync(missing local) = %v, want a not-a-directory error", err)
	}
}

func TestSyncGitLibraryPinnedTag(t *testing.T) {
	withCacheRoot(t)
	repo, commit1, _ := fixtureLibRepo(t)
	projectPath := writeProject(t, "version: 1\nlibraries:\n  - name: acme\n    git: "+repo+"\n    ref: v1.0.0\n    path: pkl\n")
	proj, err := Load(projectPath)
	if err != nil {
		t.Fatal(err)
	}

	dirs, err := proj.Sync(false)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	cacheDir, err := proj.cacheDir("acme", repo)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(cacheDir, "pkl"); len(dirs) != 1 || dirs[0] != want {
		t.Errorf("Sync = %v, want [%s]", dirs, want)
	}
	// Metadata records the resolved commit.
	meta := readMeta(cacheDir)
	if meta == nil || meta.Commit != commit1 || meta.Ref != "v1.0.0" || meta.Git != repo {
		t.Errorf("metadata = %+v, want commit %s ref v1.0.0", meta, commit1)
	}

	// Re-sync: warm pinned ref, same commit (a new commit exists on main
	// but the pin does not move).
	dirs, err = proj.Sync(false)
	if err != nil {
		t.Fatalf("re-Sync: %v", err)
	}
	if meta := readMeta(cacheDir); meta.Commit != commit1 {
		t.Errorf("pinned ref moved to %s, want %s", meta.Commit, commit1)
	}

	// Content is the pinned version.
	data, err := os.ReadFile(filepath.Join(dirs[0], "acme", "baseline.pkl"))
	if err != nil || !strings.Contains(string(data), "acme v1") {
		t.Errorf("pinned checkout content = %q, err %v", data, err)
	}
}

func TestSyncGitLibraryBranchTracks(t *testing.T) {
	withCacheRoot(t)
	repo, _, commit2 := fixtureLibRepo(t)
	projectPath := writeProject(t, "version: 1\nlibraries:\n  - name: acme\n    git: "+repo+"\n    ref: main\n    path: pkl\n")
	proj, err := Load(projectPath)
	if err != nil {
		t.Fatal(err)
	}

	if dirs, err := proj.Sync(false); err != nil {
		t.Fatalf("Sync: %v", err)
	} else if len(dirs) != 1 {
		t.Fatalf("Sync = %v, want 1 dir", dirs)
	}
	cacheDir, _ := proj.cacheDir("acme", repo)
	if meta := readMeta(cacheDir); meta.Commit != commit2 {
		t.Fatalf("branch ref resolved to %s, want tip %s", meta.Commit, commit2)
	}
}

func TestSyncOffline(t *testing.T) {
	withCacheRoot(t)
	repo, commit1, _ := fixtureLibRepo(t)

	// Cold cache + offline: a clear error.
	projCold, err := Load(writeProject(t, "version: 1\nlibraries:\n  - name: acme\n    git: "+repo+"\n    ref: v1.0.0\n    path: pkl\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := projCold.Sync(true); !errors.Is(err, ErrOfflineCold) {
		t.Errorf("Sync(offline, cold) = %v, want ErrOfflineCold", err)
	}

	// Warm cache + offline: reuse, no network.
	projWarm, err := Load(writeProject(t, "version: 1\nlibraries:\n  - name: acme\n    git: "+repo+"\n    ref: v1.0.0\n    path: pkl\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := projWarm.Sync(false); err != nil {
		t.Fatalf("warm-up Sync: %v", err)
	}
	dirs, err := projWarm.Sync(true)
	if err != nil {
		t.Fatalf("Sync(offline, warm): %v", err)
	}
	cacheDir, _ := projWarm.cacheDir("acme", repo)
	if want := filepath.Join(cacheDir, "pkl"); len(dirs) != 1 || dirs[0] != want {
		t.Errorf("Sync(offline, warm) = %v, want [%s]", dirs, want)
	}
	if meta := readMeta(cacheDir); meta.Commit != commit1 {
		t.Errorf("offline sync moved the pin to %s, want %s", meta.Commit, commit1)
	}
}

func TestStatus(t *testing.T) {
	withCacheRoot(t)
	repo, commit1, _ := fixtureLibRepo(t)
	proj, err := Load(writeProject(t, "version: 1\nlibraries:\n  - name: acme\n    git: "+repo+"\n    ref: v1.0.0\n    path: pkl\n"))
	if err != nil {
		t.Fatal(err)
	}

	sts, err := proj.Status()
	if err != nil {
		t.Fatal(err)
	}
	if sts[0].Cached || sts[0].Warm || sts[0].Commit != "" {
		t.Errorf("status before sync = %+v, want uncached", sts[0])
	}

	if _, err := proj.Sync(false); err != nil {
		t.Fatal(err)
	}
	sts, err = proj.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !sts[0].Cached || !sts[0].Warm || sts[0].Commit != commit1 {
		t.Errorf("status after sync = %+v, want cached+warm @ %s", sts[0], commit1)
	}

	// A changed ref makes the cache stale.
	proj2, err := Load(writeProject(t, "version: 1\nlibraries:\n  - name: acme\n    git: "+repo+"\n    ref: v1.1.0\n    path: pkl\n"))
	if err != nil {
		t.Fatal(err)
	}
	sts, err = proj2.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !sts[0].Cached || sts[0].Warm {
		t.Errorf("status with changed ref = %+v, want cached but stale", sts[0])
	}
}
