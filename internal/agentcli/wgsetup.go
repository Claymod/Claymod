package agentcli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/claymod/claymod/internal/wgmgr"
)

// wgSetupFile is the file `claymod enroll` writes with everything the
// host needs to bring up its WireGuard interface.
const wgSetupFile = "wg-setup.json"

// wgSetup is the on-disk shape of wg-setup.json.
type wgSetup struct {
	Interface  string     `json:"interface"`
	Overlay    string     `json:"overlay"`
	ListenPort int        `json:"listen_port"`
	PrivateKey string     `json:"private_key"`
	ServerPeer wgmgr.Peer `json:"server_peer"`
}

func NewWGSetupCmd() *cobra.Command {
	var (
		outDir string
	)
	cmd := &cobra.Command{
		Use:   "wg-setup",
		Short: "Bring up this host's WireGuard interface (root)",
		Long: `WG-setup applies the WireGuard parameters produced at
enrollment (wg-setup.json): it creates the interface if missing, assigns
the overlay address, installs the locally generated private key and adds
the control server as its peer. Requires CAP_NET_ADMIN (root).

This is the one root-only step of enrollment: everything else runs
unprivileged. For operator-managed networking, read wg-setup.json and
render the equivalent wg-quick config instead.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path := filepath.Join(outDir, wgSetupFile)
			raw, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read %s (run `claymod enroll` first): %w", path, err)
			}
			var setup wgSetup
			if err := json.Unmarshal(raw, &setup); err != nil {
				return fmt.Errorf("parse %s: %w", path, err)
			}
			if setup.Interface == "" || setup.PrivateKey == "" {
				return fmt.Errorf("%s is incomplete", path)
			}

			cfg := wgmgr.ConfConfig{
				Interface:  setup.Interface,
				Overlay:    setup.Overlay,
				ListenPort: setup.ListenPort,
				PrivateKey: setup.PrivateKey,
			}
			if err := wgmgr.EnsureAgentInterface(cfg, setup.ServerPeer); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "wireguard interface %s is up (%s)\n",
				setup.Interface, setup.Overlay)
			fmt.Fprintf(out, "  peer %s endpoint %s allowed-ips %s\n",
				setup.ServerPeer.PublicKey, setup.ServerPeer.Endpoint,
				setup.ServerPeer.AllowedIPs)
			return nil
		},
	}
	cmd.Flags().StringVar(&outDir, "out-dir", "/etc/claymod", "directory holding wg-setup.json (from `claymod enroll`)")
	return cmd
}

// writeWGSetup persists the host-side WireGuard parameters next to the
// enrolled identity files (private key included: 0600).
func writeWGSetup(outDir string, setup wgSetup) (string, error) {
	raw, err := json.MarshalIndent(setup, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(outDir, wgSetupFile)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return path, nil
}
