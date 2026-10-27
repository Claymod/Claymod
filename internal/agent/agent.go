// Package agent implements the claymod host daemon: an mTLS listener on
// the WireGuard overlay that applies primitive ops pushed by the control
// server. The agent understands only File, Command and Service ops —
// everything else is compiled away server-side.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/claymod/claymod/internal/proto"
)

// Agent serves the framed protocol on a mutual-TLS listener.
type Agent struct {
	log     *slog.Logger
	svc     ServiceRunner
	opLimit time.Duration
	// maxCapture bounds captured stdout/stderr per command (1 MiB).
	maxCapture int
}

// Options configures an Agent.
type Options struct {
	Logger *slog.Logger
	// Services executes service operations; nil selects the systemctl
	// implementation.
	Services ServiceRunner
	// OpTimeout bounds one op when the request carries no timeout.
	OpTimeout time.Duration
}

// New creates an Agent.
func New(opts Options) *Agent {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	svc := opts.Services
	if svc == nil {
		svc = SystemctlRunner{}
	}
	opLimit := opts.OpTimeout
	if opLimit <= 0 {
		opLimit = 10 * time.Minute
	}
	return &Agent{log: log, svc: svc, opLimit: opLimit, maxCapture: 1 << 20}
}

// Serve accepts connections on ln until ctx is cancelled or the listener
// fails. In-flight sessions are drained before returning (graceful
// shutdown).
func (a *Agent) Serve(ctx context.Context, ln net.Listener) error {
	var wg sync.WaitGroup
	defer wg.Wait() //nolint:waitgroup // drained on return

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		raw, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("agent: accept: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.handleConn(ctx, raw)
		}()
	}
}

func (a *Agent) handleConn(ctx context.Context, raw net.Conn) {
	remote := raw.RemoteAddr()
	conn, err := proto.Server(raw, proto.DefaultFrameTimeout)
	if err != nil {
		a.log.Warn("handshake failed", "remote", remote, "err", err)
		raw.Close()
		return
	}
	defer conn.Close()
	a.log.Debug("session open", "remote", remote, "peer", conn.Peer().Role)

	for {
		if ctx.Err() != nil {
			return
		}
		var req proto.Request
		if err := conn.Recv(&req); err != nil {
			// Peer closed or timed out: normal end of session.
			a.log.Debug("session closed", "remote", remote, "err", err)
			return
		}
		if err := a.dispatch(ctx, conn, req); err != nil {
			a.log.Warn("dispatch failed", "method", req.Method, "err", err)
			return
		}
	}
}

// dispatch handles one request. Apply streams multiple responses with the
// request's ID; other methods reply exactly once.
func (a *Agent) dispatch(ctx context.Context, conn *proto.Conn, req proto.Request) error {
	switch req.Method {
	case proto.MethodPing:
		return reply(conn, req.ID, proto.PingResult{Version: proto.Version, Agent: "claymod-agent"})
	case proto.MethodFacts:
		return reply(conn, req.ID, gatherFacts())
	case proto.MethodExec:
		var params proto.ExecParams
		if err := unmarshal(req.Params, &params); err != nil {
			return replyErr(conn, req.ID, proto.CodeBadRequest, err.Error())
		}
		res := a.exec(ctx, params)
		return reply(conn, req.ID, res)
	case proto.MethodGetFile:
		var params proto.FileParams
		if err := unmarshal(req.Params, &params); err != nil {
			return replyErr(conn, req.ID, proto.CodeBadRequest, err.Error())
		}
		res, rpcErr := a.getFile(params)
		if rpcErr != nil {
			return replyErr(conn, req.ID, rpcErr.Code, rpcErr.Message)
		}
		return reply(conn, req.ID, res)
	case proto.MethodPutFile:
		var params proto.FileParams
		if err := unmarshal(req.Params, &params); err != nil {
			return replyErr(conn, req.ID, proto.CodeBadRequest, err.Error())
		}
		if rpcErr := a.putFile(params); rpcErr != nil {
			return replyErr(conn, req.ID, rpcErr.Code, rpcErr.Message)
		}
		return reply(conn, req.ID, map[string]bool{"ok": true})
	case proto.MethodApply:
		var params proto.ApplyParams
		if err := unmarshal(req.Params, &params); err != nil {
			return replyErr(conn, req.ID, proto.CodeBadRequest, err.Error())
		}
		return a.apply(ctx, conn, req.ID, params)
	default:
		return replyErr(conn, req.ID, proto.CodeUnsupported, "unknown method "+req.Method)
	}
}

func reply(conn *proto.Conn, id string, result any) error {
	raw, err := marshal(result)
	if err != nil {
		return err
	}
	return conn.Send(proto.Response{ID: id, Result: raw})
}

func replyErr(conn *proto.Conn, id, code, msg string) error {
	return conn.Send(proto.Response{ID: id, Error: &proto.Error{Code: code, Message: msg}})
}

// gatherFacts collects basic host facts. The kernel release is read from
// procfs where available and left empty otherwise.
func gatherFacts() proto.FactsResult {
	facts := proto.FactsResult{
		Hostname: hostnameOrUnknown(),
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
	}
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		facts.Kernel = trimSpace(string(data))
	}
	return facts
}

func hostnameOrUnknown() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

func trimSpace(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}
