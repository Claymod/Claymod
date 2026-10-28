package agentcli

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/claymod/claymod/internal/enroll"
	"github.com/claymod/claymod/internal/wgmgr"
)

func NewEnrollCmd() *cobra.Command {
	var (
		serverURL string
		token     string
		hostname  string
		caFile    string
		caPin     string
		tokenOnly bool
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
of the control CA).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEnroll(cmd, enrollOptions{
				serverURL: serverURL,
				token:     token,
				hostname:  hostname,
				caFile:    caFile,
				caPin:     caPin,
				tokenOnly: tokenOnly,
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
	cmd.Flags().StringVar(&caPin, "ca-pin", "", "SHA-256 fingerprint of the control CA (hex; verified against /ca.pem)")
	cmd.Flags().BoolVar(&tokenOnly, "insecure-token-only", false,
		"skip all server authentication: the one-time token is the sole credential (used by the /enroll.sh bootstrap)")
	cmd.Flags().StringVar(&outDir, "out-dir", "/etc/claymod", "directory for the enrolled identity files")
	cmd.Flags().StringVar(&listen, "listen", "0.0.0.0:2323", "agent listen address written to agent.yaml")
	cmd.Flags().BoolVar(&skipWG, "skip-wg-config", false, "write identity files only; do not print WireGuard setup")
	cmd.Flags().IntVar(&wgPort, "wg-port", 51821, "local WireGuard listen port for the interface")
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
	tokenOnly bool
	outDir    string
	listen    string
	skipWG    bool
	wgPort    int
}

func runEnroll(cmd *cobra.Command, o enrollOptions) error {
	out := cmd.OutOrStdout()
	modes := 0
	for _, set := range []bool{o.caFile != "", o.caPin != "", o.tokenOnly} {
		if set {
			modes++
		}
	}
	if o.tokenOnly && (o.caFile != "" || o.caPin != "") {
		return fmt.Errorf("--insecure-token-only cannot be combined with --ca or --ca-pin")
	}
	if modes != 1 {
		return fmt.Errorf("choose exactly one trust mode: --ca, --ca-pin, or --insecure-token-only (pin the bootstrap server before enrolling)")
	}

	// Local WireGuard identity: generated here, never leaves the host.
	keys, err := wgmgr.GenerateKeyPair()
	if err != nil {
		return err
	}

	var client *http.Client
	if o.tokenOnly {
		// Bearer-token flow (the /enroll.sh bootstrap): no server
		// authentication — the one-time, hostname-bound token is the
		// sole credential.
		client = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion:         tls.VersionTLS13,
					InsecureSkipVerify: true,
				},
			},
		}
	} else if o.caFile != "" {
		caPEM, err := os.ReadFile(o.caFile)
		if err != nil {
			return fmt.Errorf("read CA bundle: %w", err)
		}
		client, err = enroll.NewPinnedClient(caPEM)
		if err != nil {
			return err
		}
	} else {
		// Pinned download: fetch /ca.pem over transport-only TLS and
		// verify its digest against the pin before trusting it.
		var err error
		client, err = newPinnedDownloadClient(o.serverURL, o.caPin)
		if err != nil {
			return err
		}
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

	// Everything the root-only `claymod wg-setup` needs: the local
	// private key (never transmitted — generated above) plus the control
	// server's peer parameters.
	setup := wgSetup{
		Interface:  "claymod0",
		Overlay:    resp.WGIP + "/" + strconv.Itoa(overlayPrefixLen(resp.Overlay)),
		ListenPort: o.wgPort,
		PrivateKey: keys.Private,
		ServerPeer: wgmgr.Peer{
			Hostname:            "claymod-control",
			PublicKey:           resp.WgServerPublicKey,
			AllowedIPs:          resp.Overlay,
			Endpoint:            resp.WgEndpoint,
			PersistentKeepalive: 25,
		},
	}
	if _, err := writeWGSetup(o.outDir, setup); err != nil {
		return err
	}

	if !o.skipWG {
		printWGSetup(out, o, resp, keys)
	}
	return nil
}

// printWGSetup prints the exact commands to bring up the WireGuard
// interface (documented in docs/enrollment.md). The interface itself is
// created by the operator — root is required. wg(8) expects the private
// key as a raw base64 file, so the JSON wg-keys.json must be unpacked
// first.
func printWGSetup(out io.Writer, o enrollOptions, resp *enroll.Response, keys wgmgr.KeyPair) {
	fmt.Fprintf(out, "\nWireGuard interface setup (requires root):\n")
	fmt.Fprintf(out, "  sudo claymod wg-setup --out-dir %s\n", o.outDir)
	fmt.Fprintf(out, "\n(or, for operator-managed networking, read %s/wg-setup.json\n", o.outDir)
	fmt.Fprintf(out, "and render the equivalent wg-quick config: interface %s, address %s/%s,\n",
		"claymod0", resp.WGIP, fmt.Sprint(overlayPrefixLen(resp.Overlay)))
	fmt.Fprintf(out, "peer %s endpoint %s allowed-ips %s persistent-keepalive 25)\n",
		resp.WgServerPublicKey, resp.WgEndpoint, resp.Overlay)
}

// newPinnedDownloadClient verifies the control CA by pinned download:
// it fetches GET /ca.pem over a transport-only TLS connection (the
// channel itself is untrusted on purpose) and checks the SHA-256 digest
// of the served certificate against the caller's pin. Only then is the
// bundle trusted to authenticate the enrollment call. This is the same
// trust model as the curl | sh bootstrap script — one pin, the CA.
func newPinnedDownloadClient(serverURL, wantFingerprint string) (*http.Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true, // transport untrusted: the pin is the trust
		},
	}
	fetch := &http.Client{Timeout: 15 * time.Second, Transport: transport}
	resp, err := fetch.Get(strings.TrimRight(serverURL, "/") + "/ca.pem")
	if err != nil {
		return nil, fmt.Errorf("fetch /ca.pem: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch /ca.pem: HTTP %d", resp.StatusCode)
	}
	caPEM, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read /ca.pem: %w", err)
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return nil, fmt.Errorf("/ca.pem does not contain a PEM certificate")
	}
	sum := sha256.Sum256(block.Bytes)
	if got := hex.EncodeToString(sum[:]); got != wantFingerprint {
		return nil, fmt.Errorf("CA fingerprint mismatch (got %s, want %s) — refusing to enroll",
			got, wantFingerprint)
	}
	// Trust exactly the pinned certificate: appended certificates in the
	// served bundle must never become trust roots (a MITM could serve
	// [pinned CA][rogue CA] and pass a first-block-only check).
	//
	// Hostname verification is deliberately SKIPPED here: the pin IS the
	// identity (pinned-download model), and the bootstrap certificate is
	// issued with --server-name DNS SANs only — enrolling against a bare
	// IP (https://VPS_IP:8443) must keep working. The chain is still
	// verified against the pinned CA: only the hostname check is waived.
	pinnedPool := x509.NewCertPool()
	pinnedPool.AppendCertsFromPEM(pem.EncodeToMemory(block))
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:               pinnedPool,
				MinVersion:            tls.VersionTLS13,
				InsecureSkipVerify:    true, // hostname check waived, chain checked below
				VerifyPeerCertificate: verifyChainOnly(pinnedPool),
			},
		},
	}, nil
}

// verifyChainOnly returns a VerifyPeerCertificate that validates the
// presented chain against pool but does NOT check the hostname. Used by
// the pinned-download path: the CA fingerprint pins the identity, so a
// hostname mismatch is expected and harmless (bare-IP enrollment).
func verifyChainOnly(pool *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no server certificate")
		}
		certs := make([]*x509.Certificate, 0, len(rawCerts))
		for _, der := range rawCerts {
			c, err := x509.ParseCertificate(der)
			if err != nil {
				return fmt.Errorf("parse peer certificate: %w", err)
			}
			certs = append(certs, c)
		}
		inter := x509.NewCertPool()
		for _, c := range certs[1:] {
			inter.AddCert(c)
		}
		_, err := certs[0].Verify(x509.VerifyOptions{
			Roots:         pool,
			Intermediates: inter,
			// No KeyUsages/hostname: the pin is the identity; the
			// bootstrap leaf is ServerAuth but may carry only
			// --server-name DNS SANs.
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		return err
	}
}
