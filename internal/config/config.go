// Package config loads and validates claymod server and agent
// configuration files (YAML) with sane defaults.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Server is the control-server configuration (server.yaml).
type Server struct {
	// Listen is the address of the internal control API (CLI-facing).
	Listen string `yaml:"listen"`
	// BootstrapListen is the HTTPS enrollment endpoint.
	BootstrapListen string `yaml:"bootstrap_listen"`
	// AgentPort is the port agents listen on over the WireGuard overlay.
	AgentPort int `yaml:"agent_port"`
	// AgentNetwork is the WireGuard overlay CIDR (e.g. 10.42.0.0/24).
	AgentNetwork string `yaml:"agent_network"`
	// DataDir holds the inventory DB, CA material and state.
	DataDir string `yaml:"data_dir"`
	// LogLevel is debug|info|warn|error.
	LogLevel string `yaml:"log_level"`
}

// Agent is the host-daemon configuration (/etc/claymod/agent.yaml).
type Agent struct {
	// Listen is the address to accept framed-protocol connections on,
	// normally the host's WireGuard IP on port 2323.
	Listen string `yaml:"listen"`
	// DataDir holds agent state (certs, key material).
	DataDir string `yaml:"data_dir"`
	// ServerCAFile is the PEM bundle used to verify the control server.
	ServerCAFile string `yaml:"server_ca_file"`
	// CertFile/KeyFile are the agent's mTLS client identity.
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// LogLevel is debug|info|warn|error.
	LogLevel string `yaml:"log_level"`
	// OpTimeout bounds a single Apply op when the request sets none.
	OpTimeout time.Duration `yaml:"op_timeout"`
}

// DefaultServer returns the default control-server configuration.
func DefaultServer() Server {
	return Server{
		Listen:          "127.0.0.1:8444",
		BootstrapListen: ":8443",
		AgentPort:       2323,
		AgentNetwork:    "10.42.0.0/24",
		DataDir:         "claymod-data",
		LogLevel:        "info",
	}
}

// DefaultAgent returns the default agent configuration.
func DefaultAgent() Agent {
	return Agent{
		Listen:    "0.0.0.0:2323",
		DataDir:   "/var/lib/claymod",
		LogLevel:  "info",
		OpTimeout: 10 * time.Minute,
	}
}

// LoadServer reads server.yaml from path. If path is empty, defaults are
// returned. Missing optional fields fall back to defaults.
func LoadServer(path string) (*Server, error) {
	s := DefaultServer()
	if path == "" {
		return &s, nil
	}
	if err := loadYAML(path, &s); err != nil {
		return nil, fmt.Errorf("load server config: %w", err)
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("server config %s: %w", path, err)
	}
	return &s, nil
}

// LoadAgent reads agent.yaml from path. If path is empty, defaults are
// returned.
func LoadAgent(path string) (*Agent, error) {
	a := DefaultAgent()
	if path == "" {
		return &a, nil
	}
	if err := loadYAML(path, &a); err != nil {
		return nil, fmt.Errorf("load agent config: %w", err)
	}
	if err := a.Validate(); err != nil {
		return nil, fmt.Errorf("agent config %s: %w", path, err)
	}
	return &a, nil
}

// Validate checks the server configuration.
func (s *Server) Validate() error {
	if s.Listen == "" {
		return fmt.Errorf("listen must be set")
	}
	if s.BootstrapListen == "" {
		return fmt.Errorf("bootstrap_listen must be set")
	}
	if s.AgentPort <= 0 || s.AgentPort > 65535 {
		return fmt.Errorf("agent_port must be in 1..65535, got %d", s.AgentPort)
	}
	if s.AgentNetwork == "" {
		return fmt.Errorf("agent_network must be set")
	}
	if s.DataDir == "" {
		return fmt.Errorf("data_dir must be set")
	}
	if err := validateLogLevel(s.LogLevel); err != nil {
		return err
	}
	return nil
}

// Validate checks the agent configuration.
func (a *Agent) Validate() error {
	if a.Listen == "" {
		return fmt.Errorf("listen must be set")
	}
	if a.DataDir == "" {
		return fmt.Errorf("data_dir must be set")
	}
	if a.OpTimeout <= 0 {
		return fmt.Errorf("op_timeout must be positive")
	}
	if err := validateLogLevel(a.LogLevel); err != nil {
		return err
	}
	return nil
}

// PklModulePath returns the modulepath root for PKL schema lookups,
// preferring the PKL_MODULEPATH env var and falling back to dir.
func PklModulePath(dir string) string {
	if v := os.Getenv("PKL_MODULEPATH"); v != "" {
		return v
	}
	return filepath.Clean(dir)
}

func validateLogLevel(l string) error {
	switch l {
	case "debug", "info", "warn", "error":
		return nil
	default:
		return fmt.Errorf("log_level must be debug|info|warn|error, got %q", l)
	}
}

func loadYAML(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, v)
}
