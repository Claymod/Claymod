package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/claymod/claymod/internal/agent"
	"github.com/claymod/claymod/internal/config"
	"github.com/claymod/claymod/internal/proto"
)

func newAgentCmd() *cobra.Command {
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

	certPEM, err := os.ReadFile(cfg.CertFile)
	if err != nil {
		return fmt.Errorf("read agent cert: %w", err)
	}
	keyPEM, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("read agent key: %w", err)
	}
	id, err := proto.LoadIdentity(certPEM, keyPEM)
	if err != nil {
		return err
	}
	caPEM, err := os.ReadFile(cfg.ServerCAFile)
	if err != nil {
		return fmt.Errorf("read server CA: %w", err)
	}
	clientPool, err := proto.CertPoolFromPEM(caPEM)
	if err != nil {
		return err
	}

	ln, err := proto.Listen(cfg.Listen, id, clientPool)
	if err != nil {
		return err
	}
	log.Info("agent listening", "addr", cfg.Listen)

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a := agent.New(agent.Options{
		Logger:    log,
		OpTimeout: cfg.OpTimeout,
	})
	if err := a.Serve(ctx, ln); err != nil {
		return err
	}
	log.Info("agent stopped")
	return nil
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
