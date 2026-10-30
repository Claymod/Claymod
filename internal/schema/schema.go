// Package schema resolves the shipped claymod PKL schema (base + std
// modules) and assembles the module path for playbook evaluation,
// independently of the process working directory.
//
// The std schema is embedded in the binary (pkl/embed.go) and
// materialized once into the user cache directory, so `claymod playbook
// validate|plan|apply` work from any directory. CLAYMOD_SCHEMA_DIR
// overrides the embedded std with an on-disk directory (used by the
// simulation and by installs that want to pin or edit the schema);
// CLAYMOD_MODULE_PATH and the --module-path flag add extra lookup
// directories.
package schema

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/claymod/claymod/internal/util"
	pklschema "github.com/claymod/claymod/pkl"
)

// userCacheDir is swappable in tests.
var userCacheDir = os.UserCacheDir

// CacheRoot returns the root of claymod's on-disk caches (the
// materialized std, the library clones): CLAYMOD_CACHE_DIR when set,
// otherwise the platform user cache directory. Pointing it at a
// removable/vendored directory is the air-gapped flow for libraries.
func CacheRoot() (string, error) {
	if v := os.Getenv("CLAYMOD_CACHE_DIR"); v != "" {
		return filepath.Abs(v)
	}
	return userCacheDir()
}

// readyMarker names the file written last during materialization; its
// presence (with the expected content) marks a complete schema dir.
const readyMarker = ".claymod-schema-ok"

// StdDir returns the directory searched for "modulepath:/claymod/…"
// URIs: the CLAYMOD_SCHEMA_DIR override when set, otherwise the
// embedded std materialized into the user cache directory. The
// returned path is absolute, so callers may run from any working
// directory.
func StdDir() (string, error) {
	if v := os.Getenv("CLAYMOD_SCHEMA_DIR"); v != "" {
		info, err := os.Stat(v)
		if err != nil {
			return "", fmt.Errorf("CLAYMOD_SCHEMA_DIR=%s: %w", v, err)
		}
		if !info.IsDir() {
			return "", fmt.Errorf("CLAYMOD_SCHEMA_DIR=%s is not a directory", v)
		}
		return filepath.Abs(v)
	}
	return materializeStd()
}

// materializeStd writes the embedded schema into
// <user-cache>/claymod/schema/<content-hash>/ and returns its path.
// The hash-keyed directory is written once (marker last) and reused on
// later runs, so repeated invocations never rewrite it.
func materializeStd() (string, error) {
	hash, err := embeddedHash()
	if err != nil {
		return "", err
	}
	base, err := CacheRoot()
	if err != nil {
		return "", fmt.Errorf("resolve cache dir: %w (set CLAYMOD_SCHEMA_DIR to an on-disk copy of the pkl/ schema)", err)
	}
	root := filepath.Join(base, "claymod", "schema", hash)
	if stdReady(root, hash) {
		return root, nil
	}

	// Materialize into a sibling temp dir, then rename: readers (and a
	// concurrent claymod process) never see a half-written schema.
	parent := filepath.Dir(root)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", fmt.Errorf("create schema cache dir: %w", err)
	}
	tmp, err := os.MkdirTemp(parent, ".materialize-*")
	if err != nil {
		return "", fmt.Errorf("create schema temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	if err := writeEmbedded(tmp); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(tmp, readyMarker), []byte(hash), 0o644); err != nil {
		return "", fmt.Errorf("write schema marker: %w", err)
	}
	if err := os.RemoveAll(root); err != nil { // our own cache; stale or corrupt
		return "", fmt.Errorf("replace schema cache dir: %w", err)
	}
	if err := os.Rename(tmp, root); err != nil {
		// A concurrent process may have won the rename; accept its copy.
		if stdReady(root, hash) {
			return root, nil
		}
		return "", fmt.Errorf("install schema cache dir: %w", err)
	}
	return root, nil
}

// writeEmbedded writes every embedded file under dst, creating parent
// directories as needed.
func writeEmbedded(dst string) error {
	return fs.WalkDir(pklschema.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		target := filepath.Join(dst, filepath.FromSlash(p))
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := pklschema.FS.ReadFile(p)
		if err != nil {
			return fmt.Errorf("read embedded %s: %w", p, err)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := util.WriteFileAtomic(target, data, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", p, err)
		}
		return nil
	})
}

// embeddedHash derives the cache dir name from the embedded files'
// paths and contents, so a schema change gets a fresh directory.
func embeddedHash() (string, error) {
	h := sha256.New()
	err := fs.WalkDir(pklschema.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := pklschema.FS.ReadFile(p)
		if err != nil {
			return err
		}
		fmt.Fprintf(h, "%s\x00%d\x00", p, len(data))
		h.Write(data)
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("hash embedded schema: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil))[:16], nil
}

// stdReady reports whether root holds a complete materialization of the
// expected schema version.
func stdReady(root, hash string) bool {
	data, err := os.ReadFile(filepath.Join(root, readyMarker))
	return err == nil && string(data) == hash
}

// ExtraFromEnv returns the raw CLAYMOD_MODULE_PATH entries
// (colon-separated); ModulePath expands and deduplicates them.
func ExtraFromEnv() []string {
	v := os.Getenv("CLAYMOD_MODULE_PATH")
	if v == "" {
		return nil
	}
	return strings.Split(v, ":")
}

// ModulePath assembles the ordered directories passed to `pkl eval
// --module-path`: the std root first, then extraDirs (--module-path
// flags, CLAYMOD_MODULE_PATH; project schemaPaths and library caches
// are appended by the libs package, which owns project discovery).
// Duplicates and empty entries are dropped.
func ModulePath(extraDirs []string) ([]string, error) {
	std, err := StdDir()
	if err != nil {
		return nil, err
	}
	expanded, err := expandDirs(extraDirs)
	if err != nil {
		return nil, err
	}
	dirs := []string{std}
	seen := map[string]bool{std: true}
	for _, abs := range expanded {
		if seen[abs] {
			continue
		}
		seen[abs] = true
		dirs = append(dirs, abs)
	}
	return dirs, nil
}

// expandDirs trims entries and expands a leading "~/" (the env var may
// carry shell-unexpanded paths).
func expandDirs(entries []string) ([]string, error) {
	var out []string
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		e = util.ExpandHome(e)
		abs, err := filepath.Abs(e)
		if err != nil {
			return nil, fmt.Errorf("resolve module path %s: %w", e, err)
		}
		out = append(out, abs)
	}
	return out, nil
}
