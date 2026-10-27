package util

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomicCreates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "target.txt")
	if err := WriteFileAtomic(path, []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFileAtomic returned error: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("content = %q, want hello", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("mode = %o, want 644", perm)
	}
}

func TestWriteFileAtomicOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "target.txt")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("new"), 0o644); err != nil {
		t.Fatalf("WriteFileAtomic returned error: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "new" {
		t.Errorf("content = %q, want new", got)
	}
}

func TestWriteFileAtomicLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target.txt")
	if err := WriteFileAtomic(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "target.txt" {
		names := make([]string, len(entries))
		for k, e := range entries {
			names[k] = e.Name()
		}
		t.Errorf("dir contains %v, want only target.txt", names)
	}
}

func TestWriteFileAtomicMissingDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-dir", "target.txt")
	if err := WriteFileAtomic(path, []byte("x"), 0o644); err == nil {
		t.Fatal("WriteFileAtomic succeeded in a missing directory")
	}
}

func TestCopyFilePreservesMode(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	dst := filepath.Join(dir, "dst.txt")
	if err := os.WriteFile(src, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CopyFile(src, dst); err != nil {
		t.Fatalf("CopyFile returned error: %v", err)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("dst mode = %o, want 600", perm)
	}
	got, _ := os.ReadFile(dst)
	if string(got) != "data" {
		t.Errorf("dst content = %q, want data", got)
	}
}
