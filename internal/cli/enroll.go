package cli

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/claymod/claymod/internal/enroll"
	"github.com/claymod/claymod/internal/wgmgr"
)

func newEnrollCmd() *cobra.Command {
	var (
		serverURL string
		token     string
		hostname  string
		caFile    string
		caPin     string
		outDir    string
		listen    string
		skipWG    bool
		wgPort    int
	)
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll this host with a claymod control server",
		Long: `Enroll exchanges a one-time token for host identity material
over the control server's HTTPS bootstrap endpoint: a WireGuard key pair
is generated locally (the private key never leaves this host), and the
server returns the overlay IP, CA bundle and mTLS client certificate.
Trust is pinned with --ca (PEM bundle) or --ca-pin (SHA-256 fingerprint
of the server certificate).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEnroll(cmd, enrollOptions{
				serverURL: serverURL,
				token:     token,
				hostname:  hostname,
				caFile:    caFile,
				caPin:     caPin,
				outDir:    outDir,
				listen:    listen,
				skipWG:    skipWG,
				wgPort:    wgPort,
			})
		},
	}
	cmd.Flags().StringVar(&serverURL, "server", "", "bootstrap server URL (https://host:port)")
	cmd.Flags().StringVar(&token, "token", "", "one-time enrollment token")
	cmd.Flags().StringVar(&hostname, "hostname", "", "this host's name (must match the token binding)")
	cmd.Flags().StringVar(&caFile, "ca", "", "PEM bundle used to verify the bootstrap server")
	cmd.Flags().StringVar(&caPin, "ca-pin", "", "SHA-256 fingerprint of the bootstrap server certificate (hex)")
	cmd.Flags().StringVar(&outDir, "out-dir", "/etc/claymod", "directory for the enrolled identity files")
	cmd.Flags().StringVar(&listen, "listen", "0.0.0.0:2323", "agent listen address written to agent.yaml")
	cmd.Flags().BoolVar(&skipWG, "skip-wg-config", false, "write identity files only; do not print WireGuard setup")
	cmd.Flags().IntVar(&wgPort, "wg-port", 51820, "local WireGuard listen port for the interface")
	_ = cmd.MarkFlagRequired("server")
	_ = cmd.MarkFlagRequired("token")
	_ = cmd.MarkFlagRequired("hostname")
	return cmd
}

type enrollOptions struct {
	serverURL string
	token     string
	hostname  string
	caFile    string
	caPin     string
	outDir    string
	listen    string
	skipWG    bool
	wgPort    int
}

func runEnroll(cmd *cobra.Command, o enrollOptions) error {
	out := cmd.OutOrStdout()
	if o.caFile == "" && o.caPin == "" {
		return fmt.Errorf("either --ca or --ca-pin is required (pin the bootstrap server before enrolling)")
	}

	// Local WireGuard identity: generated here, never leaves the host.
	keys, err := wgmgr.GenerateKeyPair()
	if err != nil {
		return err
	}

	var client *http.Client
	if o.caFile != "" {
		caPEM, err := os.ReadFile(o.caFile)
		if err != nil {
			return fmt.Errorf("read CA bundle: %w", err)
		}
		client, err = enroll.NewPinnedClient(caPEM)
		if err != nil {
			return err
		}
	} else {
		client = newFingerprintHTTPClient(o.caPin)
	}

	resp, err := enroll.EnrollClient(cmd.Context(), o.serverURL, client, enroll.Request{
		Token:       o.token,
		Hostname:    o.hostname,
		WgPublicKey: keys.Public,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "enrolled %s (wg ip %s)\n", resp.Hostname, resp.WGIP)

	if err := os.MkdirAll(o.outDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	write := func(name string, data []byte, mode os.FileMode) error {
		path := filepath.Join(o.outDir, name)
		if err := os.WriteFile(path, data, mode); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		fmt.Fprintf(out, "wrote %s\n", path)
		return nil
	}
	if err := write("ca.pem", resp.CACert, 0o644); err != nil {
		return err
	}
	if err := write("agent.pem", resp.ClientCert, 0o644); err != nil {
		return err
	}
	if err := write("agent-key.pem", resp.ClientKey, 0o600); err != nil {
		return err
	}

	agentYAML := fmt.Sprintf(`listen: %[5]q
data_dir: %[1]q
server_ca_file: %[2]q
cert_file: %[3]q
key_file: %[4]q
log_level: "info"
op_timeout: 10m
`,
		filepath.Join(o.outDir, "agent-data"),
		filepath.Join(o.outDir, "ca.pem"),
		filepath.Join(o.outDir, "agent.pem"),
		filepath.Join(o.outDir, "agent-key.pem"),
		o.listen,
	)
	if err := write("agent.yaml", []byte(agentYAML), 0o644); err != nil {
		return err
	}

	// The WireGuard private key stays on this host.
	wgKeys, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return err
	}
	if err := write("wg-keys.json", wgKeys, 0o600); err != nil {
		return err
	}

	if !o.skipWG {
		printWGSetup(out, o, resp, keys)
	}
	return nil
}

// printWGSetup prints the exact commands to bring up the WireGuard
// interface (documented in docs/enrollment.md). The interface itself is
// created by the operator — root is required.
func printWGSetup(out io.Writer, o enrollOptions, resp *enroll.Response, keys wgmgr.KeyPair) {
	fmt.Fprintf(out, "\nWireGuard interface setup (requires root):\n")
	fmt.Fprintf(out, "  sudo ip link add dev claymod0 type wireguard\n")
	fmt.Fprintf(out, "  sudo ip address add %s/24 dev claymod0\n", resp.WGIP)
	fmt.Fprintf(out, "  sudo wg set claymod0 private-key %s/wg-keys.json listen-port %d \\\n", o.outDir, o.wgPort)
	fmt.Fprintf(out, "    peer %s endpoint %s allowed-ips 10.42.0.0/24 persistent-keepalive 25\n", resp.WgServerPublicKey, resp.WgEndpoint)
	fmt.Fprintf(out, "  sudo ip link set up dev claymod0\n")
}

// newFingerprintHTTPClient pins the server by SHA-256 certificate
// fingerprint (InsecureSkipVerify + explicit fingerprint check: the peer
// is authenticated by pinning, not a CA chain).
func newFingerprintHTTPClient(wantFingerprint string) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS13,
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
					if len(rawCerts) == 0 {
						return fmt.Errorf("no server certificate")
					}
					sum := sha256.Sum256(rawCerts[0])
					if hex.EncodeToString(sum[:]) != wantFingerprint {
						return fmt.Errorf("server certificate fingerprint mismatch (got %s)",
							hex.EncodeToString(sum[:]))
					}
					return nil
				},
			},
		},
	}
}
