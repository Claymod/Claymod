package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultServerValid(t *testing.T) {
	s := DefaultServer()
	if err := s.Validate(); err != nil {
		t.Fatalf("default server config invalid: %v", err)
	}
}

func TestDefaultAgentValid(t *testing.T) {
	a := DefaultAgent()
	if err := a.Validate(); err != nil {
		t.Fatalf("default agent config invalid: %v", err)
	}
}

func TestLoadServerDefaultsWhenEmptyPath(t *testing.T) {
	s, err := LoadServer("")
	if err != nil {
		t.Fatalf("LoadServer(\"\") returned error: %v", err)
	}
	if want := DefaultServer(); s.Listen != want.Listen {
		t.Errorf("Listen = %q, want %q", s.Listen, want.Listen)
	}
}

func TestLoadServerOverridesDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	content := "listen: 0.0.0.0:9000\nlog_level: debug\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer returned error: %v", err)
	}
	if s.Listen != "0.0.0.0:9000" {
		t.Errorf("Listen = %q, want 0.0.0.0:9000", s.Listen)
	}
	if s.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want debug", s.LogLevel)
	}
	// Unset fields keep defaults.
	if want := DefaultServer().AgentPort; s.AgentPort != want {
		t.Errorf("AgentPort = %d, want default %d", s.AgentPort, want)
	}
}

func TestLoadServerRejectsBadLogLevel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(path, []byte("log_level: loud\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServer(path); err == nil {
		t.Fatal("LoadServer accepted invalid log_level")
	}
}

func TestLoadServerMissingFile(t *testing.T) {
	if _, err := LoadServer(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("LoadServer accepted missing file")
	}
}

func TestLoadAgentParsesOpTimeout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	content := "listen: 10.42.0.7:2323\nop_timeout: 5m\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := LoadAgent(path)
	if err != nil {
		t.Fatalf("LoadAgent returned error: %v", err)
	}
	if a.OpTimeout != 5*time.Minute {
		t.Errorf("OpTimeout = %v, want 5m", a.OpTimeout)
	}
	if a.Listen != "10.42.0.7:2323" {
		t.Errorf("Listen = %q, want 10.42.0.7:2323", a.Listen)
	}
}

func TestValidateServerBadAgentPort(t *testing.T) {
	s := DefaultServer()
	s.AgentPort = 0
	if err := s.Validate(); err == nil {
		t.Fatal("Validate accepted agent_port 0")
	}
}

func TestValidateAgentNegativeOpTimeout(t *testing.T) {
	a := DefaultAgent()
	a.OpTimeout = -1
	if err := a.Validate(); err == nil {
		t.Fatal("Validate accepted negative op_timeout")
	}
}
