package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/claymod/claymod/internal/enrollserver"
)

// TestSystemdUnitMatchesBootstrapGenerator: the static unit in docs/ and
// the one the curl|sh bootstrap generates must agree on the operational
// essentials (unit name, Restart policy, WantedBy, agent invocation) so
// manual installs and scripted installs behave identically.
func TestSystemdUnitMatchesBootstrapGenerator(t *testing.T) {
	static, err := os.ReadFile("../../docs/claymod-agent.service")
	if err != nil {
		t.Fatalf("static unit missing: %v", err)
	}
	generated := enrollserver.EnrollScript("https://control:8443")

	for _, want := range []string{
		"claymod-agent.service",
		"Restart=always",
		"RestartSec=5s",
		"WantedBy=multi-user.target",
		// ExecStart differs by design (static: concrete paths; generated:
		// $BIN_DIR/$OUT_DIR shell vars) — compare the invocation shape.
		"claymod-agent agent --config",
	} {
		if !strings.Contains(string(static), want) {
			t.Errorf("static unit missing %q", want)
		}
		if !strings.Contains(generated, want) {
			t.Errorf("bootstrap-generated unit missing %q", want)
		}
	}
}

// TestWireGuardDefaultPortNever51820: BINDING project rule — claymod
// must not default to WireGuard's standard port (users run their own
// tunnels there). Pins every flag default that carries a WG port.
func TestWireGuardDefaultPortNever51820(t *testing.T) {
	for _, tc := range []struct{ file, needle string }{
		{"serve.go", `"wg-endpoint", "127.0.0.1:51821"`},
		{"serve.go", `"wg-port", 51821`},
	} {
		src, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatalf("read %s: %v", tc.file, err)
		}
		if !strings.Contains(string(src), tc.needle) {
			t.Errorf("%s lost the 51821 default: %q not found (51820 is forbidden as a default)", tc.file, tc.needle)
		}
	}

	// The bootstrap script must never embed a hardcoded 51820 either.
	script := enrollserver.EnrollScript("https://control:8443")
	if strings.Contains(script, "51820") {
		t.Error("bootstrap script references the forbidden default port 51820")
	}
}
