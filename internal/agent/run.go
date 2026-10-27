package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/claymod/claymod/internal/config"
	"github.com/claymod/claymod/internal/proto"
)

// RunFromConfig loads agent.yaml, brings up the mTLS listener and serves
// until the context is cancelled. Shared by the standalone agent binary
// and the combined claymod binary's `agent` command.
func RunFromConfig(ctx context.Context, cfg *config.Agent, log *slog.Logger) error {
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

	a := New(Options{
		Logger:    log,
		OpTimeout: cfg.OpTimeout,
	})
	if err := a.Serve(ctx, ln); err != nil {
		return err
	}
	log.Info("agent stopped")
	return nil
}
