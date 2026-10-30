package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/claymod/claymod/internal/config"
)

// newServeCmdForTest builds the serve command and marks flags as
// explicitly set (the way argv would).
func newServeCmdForTest(t *testing.T, configPath string, set map[string]string) *cobra.Command {
	t.Helper()
	cmd := newServeCmd()
	if configPath != "" {
		if err := cmd.Flags().Set("config", configPath); err != nil {
			t.Fatal(err)
		}
	}
	for name, value := range set {
		if err := cmd.Flags().Set(name, value); err != nil {
			t.Fatalf("set --%s=%s: %v", name, value, err)
		}
	}
	return cmd
}

// writeServerConfig writes a server.yaml and returns its path.
func writeServerConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestMergeServeConfigWinsOverFlagDefaults pins the core contract: a
// config file value beats a flag's DEFAULT — only explicitly-set flags
// override. (The old behavior clobbered config data_dir with the flag
// default on every run.)
func TestMergeServeConfigWinsOverFlagDefaults(t *testing.T) {
	path := writeServerConfig(t, `data_dir: /from-config
bootstrap_listen: 127.0.0.1:9443
wg_port: 51822
manage_interface: false
wg_backend: fake
server_name: control-config
`)
	cmd := newServeCmdForTest(t, path, nil)

	cfg, err := mergeServeConfig(cmd, path)
	if err != nil {
		t.Fatalf("mergeServeConfig: %v", err)
	}
	if cfg.DataDir != "/from-config" {
		t.Errorf("DataDir = %q, want the config value (not the flag default)", cfg.DataDir)
	}
	if cfg.BootstrapListen != "127.0.0.1:9443" {
		t.Errorf("BootstrapListen = %q, want the config value", cfg.BootstrapListen)
	}
	if cfg.WGPort != 51822 || cfg.ManageInterface || cfg.WGBackend != "fake" || cfg.ServerName != "control-config" {
		t.Errorf("config values not applied: %+v", cfg)
	}
	// Unset fields keep the packaged defaults.
	if cfg.AgentNetwork != config.DefaultServer().AgentNetwork {
		t.Errorf("AgentNetwork = %q, want the default", cfg.AgentNetwork)
	}
}

func TestMergeServeConfigExplicitFlagOverrides(t *testing.T) {
	path := writeServerConfig(t, `data_dir: /from-config
wg_port: 51822
`)
	cmd := newServeCmdForTest(t, path, map[string]string{
		"data-dir":    "/from-flag",
		"wg-port":     "51825",
		"server-name": "control-flag",
	})

	cfg, err := mergeServeConfig(cmd, path)
	if err != nil {
		t.Fatalf("mergeServeConfig: %v", err)
	}
	if cfg.DataDir != "/from-flag" {
		t.Errorf("DataDir = %q, want the explicit flag value", cfg.DataDir)
	}
	if cfg.WGPort != 51825 {
		t.Errorf("WGPort = %d, want the explicit flag value", cfg.WGPort)
	}
	if cfg.ServerName != "control-flag" {
		t.Errorf("ServerName = %q, want the explicit flag value", cfg.ServerName)
	}
	// The config still governs everything the flags did not set.
	if cfg.WGBackend != config.DefaultServer().WGBackend {
		t.Errorf("WGBackend = %q, want the default", cfg.WGBackend)
	}
}

func TestMergeServeConfigRejectsInvalidResult(t *testing.T) {
	path := writeServerConfig(t, "wg_port: 51822\n")
	cmd := newServeCmdForTest(t, path, map[string]string{"wg-port": "0"})

	_, err := mergeServeConfig(cmd, path)
	if err == nil {
		t.Fatal("merge accepted wg_port 0 from an explicit flag")
	}
	if !strings.Contains(err.Error(), "wg_port") {
		t.Errorf("error = %q, want a wg_port message", err.Error())
	}
}

func TestMergeServeConfigMissingFile(t *testing.T) {
	cmd := newServeCmdForTest(t, filepath.Join(t.TempDir(), "nope.yaml"), nil)
	if _, err := mergeServeConfig(cmd, filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("merge accepted a missing config file")
	}
}
