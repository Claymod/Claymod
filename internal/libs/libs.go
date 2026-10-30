// Package libs resolves a project's claymod.project.yaml: extra local
// schema directories and external PKL libraries pinned from git repos.
//
// A library is a git repo of PKL modules (optionally under a `path:`
// subdir); a playbook repo pins it by ref in claymod.project.yaml and
// imports its modules as `import "modulepath:/<name>/…"`. Git libraries
// sync into <user-cache>/claymod/libs/<name>/ with a metadata file
// recording url, ref and resolved commit:
//
//   - pinned refs (commit sha or tag) never touch the network once
//     cached — reproducible and air-gap friendly;
//   - branch refs re-fetch on every sync (pass --offline to forbid
//     network; a warm cache is then reused as-is, a cold one errors);
//   - `path:` entries without `git:` are plain local directories (the
//     develop-a-library loop), resolved relative to the project file.
package libs

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/claymod/claymod/internal/schema"
	"github.com/claymod/claymod/internal/util"
	"gopkg.in/yaml.v3"
)

// ProjectFileName is the project file discovered by walking up from a
// playbook (or the working directory) to the filesystem root.
const ProjectFileName = "claymod.project.yaml"

// reservedName is the modulepath prefix of the shipped std; a library
// shadowing it would hijack every playbook's schema imports.
const reservedName = "claymod"

// ErrOfflineCold is wrapped when --offline meets a library with no
// cached copy.
var ErrOfflineCold = errors.New("offline and no cached copy")

// Library is one entry of the project file's `libraries:` list.
type Library struct {
	// Name is the modulepath import prefix: modulepath:/<name>/….
	Name string `yaml:"name"`
	// Git is the clone URL; empty means a plain local directory (Path,
	// relative to the project file).
	Git string `yaml:"git"`
	// Ref pins the checkout: a tag, a commit sha or a branch. Required
	// for git libraries (reproducibility by default).
	Ref string `yaml:"ref"`
	// Path is the module-dir subdir: inside the clone for git
	// libraries, relative to the project file for local ones.
	Path string `yaml:"path"`
}

// Project is a parsed claymod.project.yaml.
type Project struct {
	// Dir is the directory holding the project file (the base for
	// relative paths).
	Dir string `yaml:"-"`
	// Version is the file format version (only 1 exists).
	Version int `yaml:"version"`
	// SchemaPaths are extra local module-path directories, relative to
	// Dir.
	SchemaPaths []string `yaml:"schemaPaths"`
	// Libraries are the pinned external libraries, in file order.
	Libraries []Library `yaml:"libraries"`
}

// libMeta is the cache metadata written after a successful sync.
type libMeta struct {
	Name   string `json:"name"`
	Git    string `json:"git"`
	Ref    string `json:"ref"`
	Commit string `json:"commit"`
}

// Discover walks up from startDir looking for claymod.project.yaml.
// It returns (nil, nil) when none exists.
func Discover(startDir string) (*Project, error) {
	dir, err := filepath.Abs(startDir)
	if err != nil {
		return nil, err
	}
	for {
		p := filepath.Join(dir, ProjectFileName)
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			proj, err := Load(p)
			if err != nil {
				return nil, err
			}
			return proj, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil, nil // filesystem root, no project file
		}
		dir = parent
	}
}

// Load parses the project file at path.
func Load(path string) (*Project, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var proj Project
	if err := yaml.Unmarshal(data, &proj); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	proj.Dir = filepath.Dir(path)
	if proj.Version == 0 {
		proj.Version = 1
	}
	if err := proj.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &proj, nil
}

// Validate checks the parsed project: names unique and not reserved,
// git libraries pinned by ref, every library has a source.
func (p *Project) Validate() error {
	if p.Version != 1 {
		return fmt.Errorf("unsupported project version %d (want 1)", p.Version)
	}
	seen := map[string]bool{}
	for i, lib := range p.Libraries {
		if lib.Name == "" {
			return fmt.Errorf("library #%d: name is required", i+1)
		}
		if lib.Name == reservedName {
			return fmt.Errorf("library %q: the name %q is reserved for the shipped std", lib.Name, reservedName)
		}
		if seen[lib.Name] {
			return fmt.Errorf("library %q: duplicate name", lib.Name)
		}
		seen[lib.Name] = true
		if lib.Git == "" && lib.Path == "" {
			return fmt.Errorf("library %q: needs git (with ref) or path", lib.Name)
		}
		if lib.Git != "" && lib.Ref == "" {
			return fmt.Errorf("library %q: ref is required (pin a tag or commit for reproducibility)", lib.Name)
		}
	}
	return nil
}

// cacheDir returns the cache directory for one git library. It is keyed
// by name AND a short hash of the clone URL: two projects pinning the
// same library name from different repos must never share a checkout.
func (p *Project) cacheDir(name, gitURL string) (string, error) {
	base, err := schema.CacheRoot()
	if err != nil {
		return "", fmt.Errorf("resolve cache dir: %w", err)
	}
	sum := sha256.Sum256([]byte(gitURL))
	return filepath.Join(base, "claymod", "libs", fmt.Sprintf("%s-%x", name, sum[:4])), nil
}

// metaPath returns the metadata file inside a library's cache dir.
func metaPath(cacheDir string) string {
	return filepath.Join(cacheDir, ".claymod-lib.json")
}

// Sync returns the module-path directories for every library, syncing
// git libraries into the cache (network when needed, unless offline).
// Directories are absolute and ordered as in the project file.
func (p *Project) Sync(offline bool) ([]string, error) {
	var dirs []string
	for _, lib := range p.Libraries {
		if lib.Git == "" {
			// Local library directory.
			local := util.ExpandHome(lib.Path)
			if !filepath.IsAbs(local) {
				local = filepath.Join(p.Dir, local)
			}
			if info, err := os.Stat(local); err != nil || !info.IsDir() {
				return nil, fmt.Errorf("library %q: local path %s is not a directory", lib.Name, lib.Path)
			}
			dirs = append(dirs, local)
			continue
		}
		dir, err := p.syncGit(lib, offline)
		if err != nil {
			return nil, fmt.Errorf("library %q: %w", lib.Name, err)
		}
		dirs = append(dirs, dir)
	}
	return dirs, nil
}

// syncGit clones or refreshes one git library and returns its
// module-path directory (the checkout's `path:` subdir).
func (p *Project) syncGit(lib Library, offline bool) (string, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return "", fmt.Errorf("git CLI not found on PATH (needed to sync; install git or use a local path: library)")
	}
	cacheDir, err := p.cacheDir(lib.Name, lib.Git)
	if err != nil {
		return "", err
	}
	meta := readMeta(cacheDir)
	warm := meta != nil && meta.Git == lib.Git && meta.Ref == lib.Ref

	if _, err := os.Stat(cacheDir); err != nil {
		// Cold cache: clone (network), then checkout.
		if offline {
			return "", fmt.Errorf("%w of %q (run claymod lib sync on a connected machine)", ErrOfflineCold, lib.Name)
		}
		if _, err := gitOut("", "clone", "--quiet", lib.Git, cacheDir); err != nil {
			return "", err
		}
	} else if warm && p.refIsPinned(cacheDir, lib) {
		// Pinned ref already cached: never touch the network.
	} else if !offline {
		// Branch (or changed pin): refresh just this ref. FETCH_HEAD
		// then names exactly what was fetched.
		if _, err := gitOut(cacheDir, "fetch", "--quiet", "--force", "origin", lib.Ref); err != nil {
			return "", err
		}
	}

	if err := gitCheckout(cacheDir, lib, offline); err != nil {
		return "", err
	}
	commit, err := gitOut(cacheDir, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	if err := writeMeta(cacheDir, &libMeta{Name: lib.Name, Git: lib.Git, Ref: lib.Ref, Commit: commit}); err != nil {
		return "", err
	}

	dir := filepath.Join(cacheDir, filepath.FromSlash(lib.Path))
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return "", fmt.Errorf("checked out, but module dir %q is missing in %s", lib.Path, lib.Git)
	}
	return dir, nil
}

// refIsPinned reports whether ref is immutable: a commit sha, or a tag
// that exists in the cached clone (tags are treated as immutable once
// cached — matching the reproducibility contract).
func (p *Project) refIsPinned(cacheDir string, lib Library) bool {
	if isCommitSha(lib.Ref) {
		return true
	}
	_, err := gitOut(cacheDir, "rev-parse", "--verify", "--quiet", "refs/tags/"+lib.Ref)
	return err == nil
}

// gitCheckout brings the cached clone to the wanted ref. Pinned refs
// (and offline branch reuse) check out purely locally; when objects are
// missing, a non-offline run fetches and retries, an offline one errors.
func gitCheckout(cacheDir string, lib Library, offline bool) error {
	err := func() error {
		_, err := gitOut(cacheDir, "checkout", "--quiet", "--detach", lib.Ref)
		return err
	}()
	if err == nil {
		return nil
	}
	if offline {
		return fmt.Errorf("%w of %q at ref %q (cached copy cannot provide it)", ErrOfflineCold, lib.Name, lib.Ref)
	}
	// Fetch (tags included) and retry once; FETCH_HEAD is the fetched tip.
	if _, err := gitOut(cacheDir, "fetch", "--quiet", "--force", "--tags", "origin", lib.Ref); err != nil {
		return err
	}
	if _, err := gitOut(cacheDir, "checkout", "--quiet", "--detach", "FETCH_HEAD"); err != nil {
		return err
	}
	return nil
}

var commitShaRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

func isCommitSha(ref string) bool { return commitShaRe.MatchString(ref) }

// Status reports each library's cache state without syncing (no git
// calls, no network): for `lib list`.
type LibStatus struct {
	Library
	// Cached reports whether a metadata file exists in the cache.
	Cached bool `json:"cached"`
	// Commit is the resolved commit of the last sync ("" when absent).
	Commit string `json:"commit"`
	// Warm reports whether the cache matches the pinned git+ref.
	Warm bool `json:"warm"`
}

// Status resolves every library's cache state.
func (p *Project) Status() ([]LibStatus, error) {
	out := make([]LibStatus, 0, len(p.Libraries))
	for _, lib := range p.Libraries {
		st := LibStatus{Library: lib}
		if lib.Git != "" {
			cacheDir, err := p.cacheDir(lib.Name, lib.Git)
			if err != nil {
				return nil, err
			}
			if meta := readMeta(cacheDir); meta != nil {
				st.Cached = true
				st.Commit = meta.Commit
				st.Warm = meta.Git == lib.Git && meta.Ref == lib.Ref
			}
		}
		out = append(out, st)
	}
	return out, nil
}

// readMeta returns the cache metadata or nil when absent/corrupt.
func readMeta(cacheDir string) *libMeta {
	data, err := os.ReadFile(metaPath(cacheDir))
	if err != nil {
		return nil
	}
	var m libMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	return &m
}

func writeMeta(cacheDir string, m *libMeta) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return util.WriteFileAtomic(metaPath(cacheDir), append(data, '\n'), 0o644)
}

// gitOut runs a git command (with dir as working directory when set)
// and returns its trimmed stdout; errors carry git's stderr.
func gitOut(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), msg)
	}
	return strings.TrimSpace(string(out)), nil
}
