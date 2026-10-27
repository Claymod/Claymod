// Command certgen generates the PKI for the claymod TLS simulation. It is
// a server-side tool: it exercises the same internal/ca package the
// control server uses, and writes fixtures to a directory.
//
// Layout written to -out (default ./certs):
//
//	ca.pem              the simulation CA (trusted by both sides)
//	agent.pem           agent server certificate (ServerAuth EKU)
//	agent-key.pem       agent key
//	control.pem         control-side client certificate (ClientAuth EKU)
//	control-key.pem     control key
//	rogue-ca.pem        a second, untrusted CA (for negative probes)
//	rogue.pem           client cert from the rogue CA
//	rogue-key.pem
//	wrong-eku.pem       cert from the good CA but ServerAuth-only EKU
//	wrong-eku-key.pem
//	agent.yaml          agent configuration for the simulation
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/claymod/claymod/internal/ca"
)

func main() {
	out := flag.String("out", "certs", "output directory for generated PKI files")
	agentHost := flag.String("agent-host", "agent", "DNS name of the agent (SAN on the server cert)")
	listen := flag.String("listen", "0.0.0.0:2323", "listen address written to agent.yaml")
	flag.Parse()

	if err := run(*out, *agentHost, *listen); err != nil {
		fmt.Fprintln(os.Stderr, "certgen:", err)
		os.Exit(1)
	}
}

func run(out, agentHost, listen string) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	write := func(name string, data []byte, mode os.FileMode) error {
		path := filepath.Join(out, name)
		if err := os.WriteFile(path, data, mode); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		return nil
	}

	// Good CA: the simulation root of trust.
	authority, err := ca.New("claymod-sim-ca")
	if err != nil {
		return err
	}
	if err := write("ca.pem", authority.CertPEM(), 0o644); err != nil {
		return err
	}

	// Agent identity: TLS server, SAN covers the compose service name and
	// loopback (for the --local run).
	agentCert, agentKey, err := authority.IssueCert(ca.IssueOptions{
		CommonName:  agentHost,
		Usage:       ca.UsageServer,
		DNSNames:    []string{agentHost, "localhost"},
		IPAddresses: nil,
	})
	if err != nil {
		return err
	}
	if err := write("agent.pem", agentCert, 0o644); err != nil {
		return err
	}
	if err := write("agent-key.pem", agentKey, 0o600); err != nil {
		return err
	}

	// Control identity: TLS client.
	controlCert, controlKey, err := authority.IssueCert(ca.IssueOptions{
		CommonName: "control.sim",
		Usage:      ca.UsageClient,
	})
	if err != nil {
		return err
	}
	if err := write("control.pem", controlCert, 0o644); err != nil {
		return err
	}
	if err := write("control-key.pem", controlKey, 0o600); err != nil {
		return err
	}

	// Negative fixture 1: a client cert from an untrusted CA.
	rogue, err := ca.New("claymod-sim-rogue-ca")
	if err != nil {
		return err
	}
	if err := write("rogue-ca.pem", rogue.CertPEM(), 0o644); err != nil {
		return err
	}
	rogueCert, rogueKey, err := rogue.IssueCert(ca.IssueOptions{
		CommonName: "control.sim",
		Usage:      ca.UsageClient,
	})
	if err != nil {
		return err
	}
	if err := write("rogue.pem", rogueCert, 0o644); err != nil {
		return err
	}
	if err := write("rogue-key.pem", rogueKey, 0o600); err != nil {
		return err
	}

	// Negative fixture 2: trusted CA but ServerAuth-only EKU, presented as
	// a client certificate.
	wrongEKU, wrongKey, err := authority.IssueCert(ca.IssueOptions{
		CommonName: "wrong-eku.sim",
		Usage:      ca.UsageServer,
		DNSNames:   []string{"wrong-eku.sim"},
	})
	if err != nil {
		return err
	}
	if err := write("wrong-eku.pem", wrongEKU, 0o644); err != nil {
		return err
	}
	if err := write("wrong-eku-key.pem", wrongKey, 0o600); err != nil {
		return err
	}

	// Agent configuration for the simulation. Cert paths derive from the
	// output directory, so the same file works in compose (/certs) and in
	// a local loopback run (./certs).
	agentYAML := fmt.Sprintf(`listen: %[5]q
data_dir: %[1]q
server_ca_file: %[2]q
cert_file: %[3]q
key_file: %[4]q
log_level: "info"
op_timeout: 2m
`,
		filepath.Join(out, "agent-data"),
		filepath.Join(out, "ca.pem"),
		filepath.Join(out, "agent.pem"),
		filepath.Join(out, "agent-key.pem"),
		listen,
	)
	if err := write("agent.yaml", []byte(agentYAML), 0o644); err != nil {
		return err
	}

	fmt.Println("certgen: wrote PKI to", out)
	return nil
}
