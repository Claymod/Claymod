// Package util holds small filesystem helpers shared across claymod.
package util

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WriteFileAtomic writes data to path atomically: the content is written
// to a temporary file in the same directory, chmod'ed to mode, then
// renamed over path. Readers never observe a partial file.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".claymod-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	// Remove the temp file on failure; on success the rename consumed it.
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}

// ExpandHome expands a leading "~/" (or a bare "~") in path to the
// current user's home directory. Needed because systemd units and other
// non-shell invocations pass "~" through literally: a flag like
// --agent-bin-dir ~/claymod/agents would otherwise name a directory
// called "~". Anything else is returned unchanged.
func ExpandHome(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~"))
		}
	}
	return path
}

// CopyFile copies src to dst preserving src's permission bits.
func CopyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read %s: %w", src, err)
	}
	info, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("stat %s: %w", src, err)
	}
	if err := os.WriteFile(dst, data, info.Mode().Perm()); err != nil {
		return fmt.Errorf("write %s: %w", dst, err)
	}
	return nil
}
