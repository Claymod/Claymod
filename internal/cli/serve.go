package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/claymod/claymod/internal/config"
	"github.com/claymod/claymod/internal/enroll"
	"github.com/claymod/claymod/internal/inventory"
	"github.com/claymod/claymod/internal/state"
	"github.com/claymod/claymod/internal/wgmgr"
)

func newServeCmd() *cobra.Command {
	var (
		configPath    string
		dataDir       string
		agentNetwork  string
		bootstrapAddr string
		wgInterface   string
		wgEndpoint    string
		wgBackendMode string
		serverName    string
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the claymod control server",
		Long: `Run the claymod control server: manages hosts, issues
enrollment tokens over an HTTPS bootstrap endpoint and drives agents
over the WireGuard overlay.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(cmd.Context(), cmd, serveOptions{
				configPath:    configPath,
				dataDir:       dataDir,
				agentNetwork:  agentNetwork,
				bootstrapAddr: bootstrapAddr,
				wgInterface:   wgInterface,
				wgEndpoint:    wgEndpoint,
				wgBackendMode: wgBackendMode,
				serverName:    serverName,
			})
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to server.yaml (default values if omitted)")
	cmd.Flags().StringVar(&dataDir, "data-dir", "claymod-data", "server data directory (CA, identities, inventory)")
	cmd.Flags().StringVar(&agentNetwork, "agent-network", "10.42.0.0/24", "agent overlay CIDR (IPAM allocations)")
	cmd.Flags().StringVar(&bootstrapAddr, "bootstrap-listen", ":8443", "HTTPS enrollment listen address")
	cmd.Flags().StringVar(&wgInterface, "wg-interface", "claymod0", "WireGuard interface name (peers are managed on it)")
	cmd.Flags().StringVar(&wgEndpoint, "wg-endpoint", "127.0.0.1:51820", "WireGuard endpoint agents connect to (host:port)")
	cmd.Flags().StringVar(&wgBackendMode, "wg-backend", "wgctrl", "WireGuard backend: wgctrl (real, needs root) or fake (testing)")
	cmd.Flags().StringVar(&serverName, "server-name", "claymod", "CN/SAN on the bootstrap server certificate (agents pin it)")
	return cmd
}

type serveOptions struct {
	configPath    string
	dataDir       string
	agentNetwork  string
	bootstrapAddr string
	wgInterface   string
	wgEndpoint    string
	wgBackendMode string
	serverName    string
}

func runServe(ctx context.Context, cmd *cobra.Command, o serveOptions) error {
	cfg, err := config.LoadServer(o.configPath)
	if err != nil {
		return err
	}
	if o.dataDir != "" {
		cfg.DataDir = o.dataDir
	}
	if o.agentNetwork != "" {
		cfg.AgentNetwork = o.agentNetwork
	}
	log := newLogger(cfg.LogLevel)

	st, err := state.Open(cfg.DataDir, o.serverName)
	if err != nil {
		return err
	}
	inv, err := inventory.Open(st.InventoryPath, cfg.AgentNetwork)
	if err != nil {
		return err
	}
	defer inv.Close()

	var backend wgmgr.Backend
	switch o.wgBackendMode {
	case "fake":
		backend = wgmgr.NewFakeBackend()
		log.Warn("using fake wireguard backend (peers are not installed on a real interface)")
	case "wgctrl", "":
		backend = wgmgr.NewWgctrlBackend(o.wgInterface)
	default:
		return fmt.Errorf("unknown wireguard backend %q (want wgctrl or fake)", o.wgBackendMode)
	}
	wgMgr := wgmgr.NewWithKeys(o.wgInterface, st.WGKeys, backend, o.wgEndpoint)

	enrollSrv := enroll.NewServer(inv, st.CA, wgMgr, log)
	mux := enrollSrv.Handler()

	srv := &http.Server{
		Addr:    o.bootstrapAddr,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{st.ServerID.Certificate},
			MinVersion:   tls.VersionTLS13,
		},
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Info("bootstrap endpoint listening (https)",
		"addr", o.bootstrapAddr, "server_name", o.serverName)
	// Print the certificate fingerprint: enroll clients pin it with
	// --ca-pin (see docs/enrollment.md).
	if leaf := st.ServerID.Certificate.Certificate; len(leaf) > 0 {
		sum := sha256.Sum256(leaf[0])
		fmt.Fprintf(cmd.OutOrStdout(),
			"bootstrap certificate fingerprint (pin with --ca-pin):\n  %s\n",
			hex.EncodeToString(sum[:]))
	}

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		// Certificates come from state (internal CA), not files:
		// tls.Config.Certificates is preloaded, so GetCertificate is nil.
		errCh <- srv.ListenAndServeTLS("", "")
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		log.Info("shutting down")
		return srv.Shutdown(shutdownCtx)
	}
}

func newHostCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "host",
		Short: "Manage enrollment tokens and hosts",
	}
	cmd.AddCommand(newHostTokenCmd())
	cmd.AddCommand(newHostListCmd())
	cmd.AddCommand(newHostFactsCmd())
	cmd.AddCommand(newHostRevokeCmd())
	return cmd
}

func newHostTokenCmd() *cobra.Command {
	var (
		configPath string
		dataDir    string
		tokenFile  string
		ttl        time.Duration
	)
	cmd := &cobra.Command{
		Use:   "token <hostname>",
		Short: "Create a one-time enrollment token for a host",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadServer(configPath)
			if err != nil {
				return err
			}
			// Host subcommands touch only the inventory: opening the full
			// server state here would create the bootstrap certificate
			// before `serve` runs (with the wrong name).
			if dataDir != "" {
				cfg.DataDir = dataDir
			}
			inv, err := inventory.Open(filepath.Join(cfg.DataDir, "inventory.db"), cfg.AgentNetwork)
			if err != nil {
				return err
			}
			defer inv.Close()

			token, err := generateToken()
			if err != nil {
				return err
			}
			if err := inv.StoreToken(token, args[0], time.Now().Add(ttl)); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "enrollment token for %s (valid %s):\n  %s\n", args[0], ttl, token)
			fmt.Fprintf(out, "on the host, run:\n  claymod enroll --server https://<control-host>:8443 --token %s --hostname %s --ca-pin <sha256-of-bootstrap-cert>\n", token, args[0])
			if tokenFile != "" {
				if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0o600); err != nil {
					return fmt.Errorf("write token file: %w", err)
				}
				fmt.Fprintf(out, "token also written to %s\n", tokenFile)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to server.yaml")
	cmd.Flags().StringVar(&dataDir, "data-dir", "claymod-data", "server data directory")
	cmd.Flags().StringVar(&tokenFile, "token-file", "", "also write the raw token to this file (for scripted enrollment)")
	cmd.Flags().DurationVar(&ttl, "ttl", 15*time.Minute, "token validity")
	return cmd
}

func newHostListCmd() *cobra.Command {
	var (
		configPath string
		dataDir    string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List enrolled hosts",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadServer(configPath)
			if err != nil {
				return err
			}
			if dataDir != "" {
				cfg.DataDir = dataDir
			}
			inv, err := inventory.Open(filepath.Join(cfg.DataDir, "inventory.db"), cfg.AgentNetwork)
			if err != nil {
				return err
			}
			defer inv.Close()

			hosts, err := inv.ListHosts()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if len(hosts) == 0 {
				fmt.Fprintln(out, "no hosts enrolled")
				return nil
			}
			for _, h := range hosts {
				key := h.PublicKey
				if len(key) > 12 {
					key = key[:12] + "…"
				}
				fmt.Fprintf(out, "%-20s %s wg-key=%s\n", h.Hostname, h.WGIP, key)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to server.yaml")
	cmd.Flags().StringVar(&dataDir, "data-dir", "claymod-data", "server data directory")
	return cmd
}

func newHostRevokeCmd() *cobra.Command {
	var (
		configPath    string
		dataDir       string
		wgInterface   string
		wgBackendMode string
	)
	cmd := &cobra.Command{
		Use:   "revoke <hostname>",
		Short: "Revoke a host: drop its peer, IP and certificate trust",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadServer(configPath)
			if err != nil {
				return err
			}
			if dataDir != "" {
				cfg.DataDir = dataDir
			}
			inv, err := inventory.Open(filepath.Join(cfg.DataDir, "inventory.db"), cfg.AgentNetwork)
			if err != nil {
				return err
			}
			defer inv.Close()

			// Revocation needs the inventory (host row + revocation
			// serial) and the WG backend; no CA or server state.
			var backend wgmgr.Backend
			switch wgBackendMode {
			case "fake":
				backend = wgmgr.NewFakeBackend()
			case "wgctrl", "":
				backend = wgmgr.NewWgctrlBackend(wgInterface)
			default:
				return fmt.Errorf("unknown wireguard backend %q (want wgctrl or fake)", wgBackendMode)
			}
			wgMgr := wgmgr.NewWithKeys(wgInterface, wgmgr.KeyPair{}, backend, "")
			enrollSrv := enroll.NewServer(inv, nil, wgMgr, newLogger(cfg.LogLevel))

			if err := enrollSrv.Revoke(args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "revoked %s (peer removed, IP freed, certificate serial revoked)\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to server.yaml")
	cmd.Flags().StringVar(&dataDir, "data-dir", "claymod-data", "server data directory")
	cmd.Flags().StringVar(&wgInterface, "wg-interface", "claymod0", "WireGuard interface name")
	cmd.Flags().StringVar(&wgBackendMode, "wg-backend", "wgctrl", "WireGuard backend: wgctrl (real, needs root) or fake (testing)")
	return cmd
}

// generateToken returns a URL-safe random 256-bit token.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
