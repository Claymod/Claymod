package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/claymod/claymod/internal/config"
	"github.com/claymod/claymod/internal/enrollserver"
	"github.com/claymod/claymod/internal/inventory"
	"github.com/claymod/claymod/internal/state"
	"github.com/claymod/claymod/internal/util"
	"github.com/claymod/claymod/internal/wgmanager"
	"github.com/claymod/claymod/internal/wgmgr"
)

func newServeCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the claymod control server",
		Long: `Run the claymod control server: manages hosts, issues
enrollment tokens over an HTTPS bootstrap endpoint and drives agents
over the WireGuard overlay.

The YAML config file (--config server.yaml) is the primary source of
parameters; every CLI flag overrides only when it is explicitly given.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(cmd.Context(), cmd, configPath)
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to server.yaml (the primary configuration source; defaults if omitted)")
	// Flags carry their defaults for --help only: mergeServeConfig uses
	// a value ONLY when the flag was explicitly set, so the config file
	// always wins over defaults.
	cmd.Flags().String("data-dir", "claymod-data", "server data directory (CA, identities, inventory)")
	cmd.Flags().String("agent-network", "10.42.0.0/24", "agent overlay CIDR (IPAM allocations)")
	cmd.Flags().String("bootstrap-listen", ":8443", "HTTPS enrollment listen address")
	cmd.Flags().String("wg-interface", "claymod0", "WireGuard interface name (peers are managed on it)")
	cmd.Flags().String("wg-endpoint", "127.0.0.1:51821", "WireGuard endpoint agents connect to (host:port)")
	cmd.Flags().Int("wg-port", 51821, "WireGuard UDP listen port (written to the generated config)")
	cmd.Flags().String("agent-bin-dir", "", "directory of claymod-agent binaries to serve at /agent/{goos}/{goarch} (default: <data-dir>/agents)")
	cmd.Flags().Bool("manage-interface", true, "create/refresh the WireGuard interface at startup (needs CAP_NET_ADMIN); --manage-interface=false to drive wg-quick yourself")
	cmd.Flags().String("wg-backend", "wgctrl", "WireGuard backend: wgctrl (real, needs root) or fake (testing)")
	cmd.Flags().String("server-name", "claymod", "CN/SAN on the bootstrap server certificate (agents pin it)")
	return cmd
}

// mergeServeConfig loads the server.yaml config (the primary source,
// with its own defaults) and applies ONLY the CLI flags the user
// explicitly set — flag defaults never clobber config values.
func mergeServeConfig(cmd *cobra.Command, configPath string) (*config.Server, error) {
	cfg, err := config.LoadServer(configPath)
	if err != nil {
		return nil, err
	}
	f := cmd.Flags()
	setString := func(name string, dst *string) {
		if f.Changed(name) {
			v, _ := f.GetString(name)
			*dst = v
		}
	}
	setInt := func(name string, dst *int) {
		if f.Changed(name) {
			v, _ := f.GetInt(name)
			*dst = v
		}
	}
	setBool := func(name string, dst *bool) {
		if f.Changed(name) {
			v, _ := f.GetBool(name)
			*dst = v
		}
	}
	setString("data-dir", &cfg.DataDir)
	setString("agent-network", &cfg.AgentNetwork)
	setString("bootstrap-listen", &cfg.BootstrapListen)
	setString("server-name", &cfg.ServerName)
	setString("wg-interface", &cfg.WGInterface)
	setString("wg-endpoint", &cfg.WGEndpoint)
	setInt("wg-port", &cfg.WGPort)
	setString("agent-bin-dir", &cfg.AgentBinDir)
	setBool("manage-interface", &cfg.ManageInterface)
	setString("wg-backend", &cfg.WGBackend)
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("server configuration (config file + flags): %w", err)
	}
	return cfg, nil
}

func runServe(ctx context.Context, cmd *cobra.Command, configPath string) error {
	cfg, err := mergeServeConfig(cmd, configPath)
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel)

	st, err := state.Open(cfg.DataDir, cfg.ServerName)
	if err != nil {
		return err
	}
	inv, err := inventory.Open(st.InventoryPath, cfg.AgentNetwork)
	if err != nil {
		return err
	}
	defer inv.Close()

	var backend wgmanager.Backend
	switch cfg.WGBackend {
	case "fake":
		backend = wgmanager.NewFakeBackend()
		log.Warn("using fake wireguard backend (peers are not installed on a real interface)")
	case "wgctrl", "":
		backend = wgmanager.NewWgctrlBackend(cfg.WGInterface)
	default:
		return fmt.Errorf("unknown wireguard backend %q (want wgctrl or fake)", cfg.WGBackend)
	}
	wgMgr := wgmanager.NewWithKeys(cfg.WGInterface, st.WGKeys, backend, cfg.WGEndpoint)
	wgMgr.Overlay = inv.ServerIP() + "/" + strconv.Itoa(overlayPrefixLen(cfg.AgentNetwork))
	wgMgr.ListenPort = cfg.WGPort
	wgMgr.ConfPath = wgmgr.ConfPath(cfg.DataDir, cfg.WGInterface)
	// The inventory is the source of truth for the config file: serve
	// and `host revoke` both regenerate from it, so neither can
	// resurrect a peer the other removed.
	wgMgr.PeersFunc = func() ([]wgmgr.Peer, error) {
		return inventoryPeers(inv)
	}

	// Reinstall peers from the inventory (a restart must not lose the
	// overlay) and rewrite the interface configuration.
	peers, err := wgMgr.PeersFunc()
	if err != nil {
		return err
	}
	if err := wgMgr.Resync(peers); err != nil {
		return fmt.Errorf("resync wireguard peers: %w", err)
	}
	log.Info("wireguard configuration written", "path", wgMgr.ConfPath, "peers", len(peers))

	switch {
	case cfg.WGBackend == "fake":
		// Testing mode: there is no real WireGuard interface to
		// manage (the README loopback demo and the simulation run
		// without CAP_NET_ADMIN).
		log.Info("wireguard interface not managed (fake backend)")
	case cfg.ManageInterface:
		if err := wgmgr.EnsureInterface(wgMgr.ConfConfig()); err != nil {
			return fmt.Errorf("manage-interface: %w", err)
		}
		log.Info("wireguard interface ensured", "interface", cfg.WGInterface)
	default:
		log.Info("wireguard interface is operator-managed (manage_interface: false; apply the generated config with wg-quick / wg syncconf)")
	}

	agentDir := cfg.AgentBinDir
	if agentDir == "" {
		agentDir = filepath.Join(cfg.DataDir, "agents")
	}
	// Expand "~/" (a systemd unit's ExecStart has no shell, so a
	// --agent-bin-dir ~/claymod/agents would otherwise name a
	// directory literally called "~").
	agentDir = util.ExpandHome(agentDir)
	enrollSrv := enrollserver.NewServer(inv, st.CA, wgMgr, log)
	enrollSrv.AgentBinDir = agentDir
	if digests, err := enrollserver.AgentDigests(agentDir); err == nil && len(digests) > 0 {
		log.Info("agent binaries offered for download", "dir", agentDir)
		for _, d := range digests {
			cmd.Printf("agent binary %s\n", d)
		}
	} else if _, err := os.Stat(agentDir); err != nil {
		log.Warn("no agent binaries to serve: directory does not exist (create it and drop the release assets claymod-agent-<goos>-<goarch> in)",
			"dir", agentDir)
	} else {
		log.Warn("no agent binaries to serve: no claymod-agent-<goos>-<goarch> files here (release asset names, e.g. claymod-agent-linux-amd64)",
			"dir", agentDir)
	}
	mux := enrollSrv.Handler()

	srv := &http.Server{
		Addr:    cfg.BootstrapListen,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{st.ServerID.Certificate},
			MinVersion:   tls.VersionTLS13,
		},
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Info("bootstrap endpoint listening (https)",
		"addr", cfg.BootstrapListen, "server_name", cfg.ServerName)
	// The CA fingerprint pins `--ca-pin` enrollment (and `--ca`
	// verification); the one-liner is token-only.
	out := cmd.OutOrStdout()
	if block, _ := pem.Decode(st.CA.CertPEM()); block != nil {
		sum := sha256.Sum256(block.Bytes)
		fp := hex.EncodeToString(sum[:])
		fmt.Fprintf(out,
			"CA fingerprint (the pin for agent enroll --ca-pin/--ca)\n  %s\n", fp)
		fmt.Fprintf(out,
			"one-liner enroll for hosts (the token is the credential):\n  curl -fsSLk \\\n    https://<control-host>:8443/enroll.sh | sudo sh -s -- --token <token> --hostname <name>\n")
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
			if cmd.Flags().Changed("data-dir") {
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
			fmt.Fprintf(out, "on the host, download the agent and enroll:\n")
			fmt.Fprintf(out, "  curl --cacert ca.pem -o claymod-agent https://<control-host>:8443/agent/$(go env GOOS 2>/dev/null || uname -s | tr A-Z a-z)/$(go env GOARCH 2>/dev/null || uname -m | sed s/x86_64/amd64/) && chmod +x claymod-agent\n")
			fmt.Fprintf(out, "  ./claymod-agent enroll --server https://<control-host>:8443 --token %s --hostname %s --ca-pin <CA fingerprint>\n", token, args[0])
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
			if cmd.Flags().Changed("data-dir") {
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
			if cmd.Flags().Changed("data-dir") {
				cfg.DataDir = dataDir
			}
			inv, err := inventory.Open(filepath.Join(cfg.DataDir, "inventory.db"), cfg.AgentNetwork)
			if err != nil {
				return err
			}
			defer inv.Close()

			// Revocation needs the inventory (host row + revocation
			// serial), the WireGuard state (peer removal + conf rewrite)
			// and the WG backend. State is loaded, never created.
			st, err := state.Load(cfg.DataDir)
			if err != nil {
				return err
			}
			var backend wgmanager.Backend
			switch wgBackendMode {
			case "fake":
				backend = wgmanager.NewFakeBackend()
			case "wgctrl", "":
				backend = wgmanager.NewWgctrlBackend(wgInterface)
			default:
				return fmt.Errorf("unknown wireguard backend %q (want wgctrl or fake)", wgBackendMode)
			}
			wgMgr := wgmanager.NewWithKeys(wgInterface, st.WGKeys, backend, "")
			wgMgr.ConfPath = wgmgr.ConfPath(cfg.DataDir, wgInterface)
			wgMgr.PeersFunc = func() ([]wgmgr.Peer, error) {
				return inventoryPeers(inv)
			}
			enrollSrv := enrollserver.NewServer(inv, st.CA, wgMgr, newLogger(cfg.LogLevel))

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

// inventoryPeers maps enrolled hosts to WireGuard peers (skip hosts
// without a key: enrolled before WireGuard keys existed).
func inventoryPeers(inv *inventory.Inventory) ([]wgmgr.Peer, error) {
	hosts, err := inv.ListHosts()
	if err != nil {
		return nil, err
	}
	peers := make([]wgmgr.Peer, 0, len(hosts))
	for _, h := range hosts {
		if h.PublicKey == "" {
			continue
		}
		peers = append(peers, wgmgr.Peer{
			Hostname:   h.Hostname,
			PublicKey:  h.PublicKey,
			AllowedIPs: h.WGIP + "/32",
		})
	}
	return peers, nil
}

// overlayPrefixLen returns the prefix length of a CIDR string (default
// 24 when unparsable).
func overlayPrefixLen(cidr string) int {
	_, p, err := net.ParseCIDR(cidr)
	if err != nil {
		return 24
	}
	ones, _ := p.Mask.Size()
	return ones
}

// generateToken returns a URL-safe random 256-bit token.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
