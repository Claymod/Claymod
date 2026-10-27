package agentcli

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/claymod/claymod/internal/agent"
	"github.com/claymod/claymod/internal/config"
)

// NewAgentCmd runs the claymod host agent.
func NewAgentCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Run the claymod host agent",
		Long: `Run the claymod host agent: an mTLS listener on the WireGuard
overlay that applies primitive ops pushed by the control server.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAgent(cmd.Context(), configPath)
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to agent.yaml (default values if omitted)")
	return cmd
}

func runAgent(ctx context.Context, configPath string) error {
	cfg, err := config.LoadAgent(configPath)
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel)
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return agent.RunFromConfig(ctx, cfg, log)
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

// overlayPrefixLen returns the prefix length of a CIDR string (default
// 24 when unparsable). Duplicated from the server CLI so this package
// stays free of server-side imports.
func overlayPrefixLen(cidr string) int {
	_, p, err := net.ParseCIDR(cidr)
	if err != nil {
		return 24
	}
	ones, _ := p.Mask.Size()
	return ones
}
