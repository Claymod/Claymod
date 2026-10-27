package enrollserver

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentDownloadServesBinary(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("fake agent binary")
	if err := os.WriteFile(filepath.Join(dir, "claymod-agent-linux-amd64"), payload, 0o755); err != nil {
		t.Fatal(err)
	}
	s := &Server{AgentBinDir: dir}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/agent/linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	buf := make([]byte, len(payload))
	resp.Body.Read(buf)
	if string(buf) != string(payload) {
		t.Errorf("body = %q, want the payload", buf)
	}

	// The .sha256 sidecar matches the payload digest.
	resp, err = http.Get(ts.URL + "/agent/linux/amd64.sha256")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	sum := sha256.Sum256(payload)
	want := hex.EncodeToString(sum[:])
	got := make([]byte, 200)
	n, _ := resp.Body.Read(got)
	if !strings.Contains(string(got[:n]), want) {
		t.Errorf("digest body = %q, want %s", got[:n], want)
	}
}

func TestAgentDownloadMissingAndUnknown(t *testing.T) {
	s := &Server{AgentBinDir: t.TempDir()}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	for _, path := range []string{
		"/agent/windows/amd64", // unknown platform
		"/agent/linux/riscv64", // unknown arch
		"/agent/linux",         // malformed
		"/agent/linux/amd64",   // known but no binary on disk
	} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s status = %d, want 404", path, resp.StatusCode)
		}
	}
}

func TestAgentDownloadDisabledWithoutDir(t *testing.T) {
	s := &Server{}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/agent/linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when --agent-bin-dir is unset", resp.StatusCode)
	}
}

func TestAgentDigestsListsFiles(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("agent")
	os.WriteFile(filepath.Join(dir, "claymod-agent-linux-arm64"), payload, 0o755)
	os.WriteFile(filepath.Join(dir, "claymod-agent-darwin-arm64"), payload, 0o755)
	os.WriteFile(filepath.Join(dir, "README"), []byte("ignore"), 0o644)

	lines, err := AgentDigests(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 {
		t.Fatalf("AgentDigests = %v, want 2 lines", lines)
	}
	sum := sha256.Sum256(payload)
	for _, line := range lines {
		if !strings.Contains(line, hex.EncodeToString(sum[:])) {
			t.Errorf("line %q missing the payload digest", line)
		}
		if !strings.HasPrefix(line, "darwin-") && !strings.HasPrefix(line, "linux-") {
			t.Errorf("line %q should start with goos-goarch", line)
		}
	}
	_ = fmt.Sprint() // keep fmt import honest
}
