package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/claymod/claymod/internal/ca"
	"github.com/claymod/claymod/internal/proto"
)

// probeOptions configures one control-side TLS probe run.
type probeOptions struct {
	addr         string
	serverName   string
	caFile       string
	certFile     string
	keyFile      string
	smokePath    string
	expectReject bool
}

func newProbeCmd() *cobra.Command {
	var o probeOptions
	cmd := &cobra.Command{
		Use:   "probe",
		Short: "Probe an agent over mTLS (control-server side)",
		Long: `Probe dials an agent over the framed mTLS protocol and runs a
Ping, Facts and a two-pass Apply smoke (the second pass must be a no-op).
With --expect-reject it asserts the connection is REFUSED instead, for
negative TLS checks (bad client cert, wrong EKU, untrusted CA).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProbe(cmd.Context(), cmd.OutOrStdout(), o)
		},
	}
	cmd.Flags().StringVar(&o.addr, "addr", "", "agent address (host:port)")
	cmd.Flags().StringVar(&o.serverName, "server-name", "", "TLS server name to verify (default: host part of --addr)")
	cmd.Flags().StringVar(&o.caFile, "ca", "", "PEM file with the CA used to verify the agent")
	cmd.Flags().StringVar(&o.certFile, "cert", "", "PEM file with the probe's client certificate")
	cmd.Flags().StringVar(&o.keyFile, "key", "", "PEM file with the probe's client key")
	cmd.Flags().StringVar(&o.smokePath, "smoke-path", "/tmp/claymod-probe-smoke.txt", "absolute path used by the Apply smoke test")
	cmd.Flags().BoolVar(&o.expectReject, "expect-reject", false, "assert that the TLS/protocol handshake is refused")
	_ = cmd.MarkFlagRequired("addr")
	_ = cmd.MarkFlagRequired("ca")
	return cmd
}

func runProbe(ctx context.Context, out io.Writer, o probeOptions) error {
	if o.serverName == "" {
		o.serverName = hostOfAddr(o.addr)
	}
	caPEM, err := os.ReadFile(o.caFile)
	if err != nil {
		return fmt.Errorf("read CA: %w", err)
	}
	pool, err := proto.CertPoolFromPEM(caPEM)
	if err != nil {
		return err
	}
	var id proto.Identity
	switch {
	case o.certFile == "" && o.keyFile == "":
		fmt.Fprintf(out, "probe identity: none (anonymous client)\n")
	case o.certFile == "" || o.keyFile == "":
		return fmt.Errorf("--cert and --key must be given together")
	default:
		certPEM, err := os.ReadFile(o.certFile)
		if err != nil {
			return fmt.Errorf("read client cert: %w", err)
		}
		keyPEM, err := os.ReadFile(o.keyFile)
		if err != nil {
			return fmt.Errorf("read client key: %w", err)
		}
		id, err = proto.LoadIdentity(certPEM, keyPEM)
		if err != nil {
			return err
		}
		if cert, err := ca.ParseCertPEM(certPEM); err == nil {
			fmt.Fprintf(out, "probe identity: CN=%s\n", cert.Subject.CommonName)
		}
	}

	conn, err := proto.Dial(o.addr, o.serverName, id, pool)
	if o.expectReject {
		if err == nil {
			conn.Close()
			return fmt.Errorf("expected rejection but connection to %s succeeded", o.addr)
		}
		fmt.Fprintf(out, "REJECTED as expected: %v\n", err)
		return nil
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Fprintf(out, "TLS handshake OK (peer role=%s protocol v%d)\n", conn.Peer().Role, conn.Peer().Version)

	var ping proto.PingResult
	if err := call(conn, "probe-ping", proto.MethodPing, nil, &ping); err != nil {
		return fmt.Errorf("ping: %w", err)
	}
	fmt.Fprintf(out, "Ping OK (agent=%s protocol v%d)\n", ping.Agent, ping.Version)

	var facts proto.FactsResult
	if err := call(conn, "probe-facts", proto.MethodFacts, nil, &facts); err != nil {
		return fmt.Errorf("facts: %w", err)
	}
	fmt.Fprintf(out, "Facts OK (host=%s os=%s arch=%s kernel=%s)\n",
		facts.Hostname, facts.OS, facts.Arch, facts.Kernel)

	ops := []proto.Op{{
		OpType: proto.OpTypeFile,
		File:   &proto.FileOp{Path: o.smokePath, Content: "claymod probe smoke\n", Mode: "0644"},
	}}
	first, err := probeApply(conn, ops)
	if err != nil {
		return fmt.Errorf("apply 1: %w", err)
	}
	if first.Failures != 0 {
		return fmt.Errorf("apply 1 reported %d failure(s): %+v", first.Failures, first)
	}
	second, err := probeApply(conn, ops)
	if err != nil {
		return fmt.Errorf("apply 2: %w", err)
	}
	if second.Failures != 0 {
		return fmt.Errorf("apply 2 reported %d failure(s): %+v", second.Failures, second)
	}
	if second.Changes != 0 {
		return fmt.Errorf("apply is not idempotent over TLS: 2nd pass changed %d thing(s)", second.Changes)
	}
	fmt.Fprintf(out, "Apply smoke OK over TLS (1st pass: %d change(s), 2nd pass: no-op)\n", first.Changes)
	fmt.Fprintf(out, "PROBE OK\n")
	return nil
}

// call sends one request and decodes a single response.
func call(conn *proto.Conn, id, method string, params any, result any) error {
	req := proto.Request{ID: id, Method: method}
	if params != nil {
		raw, err := json.Marshal(params)
		if err != nil {
			return err
		}
		req.Params = raw
	}
	rpcErr, err := conn.Call(req, result)
	if err != nil {
		return err
	}
	if rpcErr != nil {
		return rpcErr
	}
	return nil
}

// probeApply runs one Apply and returns its summary result.
func probeApply(conn *proto.Conn, ops []proto.Op) (proto.ApplyResult, error) {
	id := fmt.Sprintf("probe-apply-%d", time.Now().UnixNano())
	params, err := json.Marshal(proto.ApplyParams{Ops: ops})
	if err != nil {
		return proto.ApplyResult{}, err
	}
	if err := conn.Send(proto.Request{ID: id, Method: proto.MethodApply, Params: params}); err != nil {
		return proto.ApplyResult{}, err
	}
	for {
		var resp proto.Response
		if err := conn.Recv(&resp); err != nil {
			return proto.ApplyResult{}, err
		}
		if resp.ID != id {
			return proto.ApplyResult{}, fmt.Errorf("response id %q does not match %q", resp.ID, id)
		}
		if resp.Error != nil {
			return proto.ApplyResult{}, resp.Error
		}
		var r proto.ApplyResult
		if err := json.Unmarshal(resp.Result, &r); err != nil {
			return proto.ApplyResult{}, err
		}
		if r.Summary {
			return r, nil
		}
	}
}

// hostOfAddr extracts the host part of a host:port address.
func hostOfAddr(addr string) string {
	if k := strings.LastIndex(addr, ":"); k > 0 {
		return addr[:k]
	}
	return addr
}
