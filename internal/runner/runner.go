// Package runner executes compiled playbook ops against enrolled agents
// over the framed mTLS protocol: it dials each host, streams Apply ops in
// plan order and collects per-op results into a run report. Hosts run in
// parallel (worker pool); per-host failure policy is fail-fast or continue.
package runner

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/claymod/claymod/internal/proto"
)

// DefaultParallelism is the number of hosts applied to concurrently.
const DefaultParallelism = 5

// Target is one agent endpoint to apply to.
type Target struct {
	// Hostname is the inventory hostname (report label).
	Hostname string
	// Addr is the agent's dial address (WG IP:port).
	Addr string
	// ServerName is the TLS name verified against the agent's
	// certificate (normally the hostname).
	ServerName string
}

// HostSpec pairs a target with the ops to apply there. Ops are compiled
// per host (per-host rendering) and already in dependency order.
type HostSpec struct {
	Target Target
	Ops    []proto.Op
}

// Request is one apply run across hosts.
type Request struct {
	// Hosts are the per-host op sets to apply.
	Hosts []HostSpec
	// Identity is the control server's client certificate.
	Identity proto.Identity
	// ServerPool verifies the agents' server certificates.
	ServerPool *x509.CertPool
}

// Options control execution policy.
type Options struct {
	// Check reports would-change without mutating anything (agent-side).
	Check bool
	// MaxFailures is the number of failed hosts tolerated before the
	// remaining hosts are skipped: -1 = run all (continue), 0 = fail-fast
	// on the first failed host, N = skip after N failed hosts.
	MaxFailures int
	// Parallelism is the worker pool size (default DefaultParallelism).
	Parallelism int
	// Timeout optionally caps one agent-side Apply run (0 = agent
	// default).
	Timeout time.Duration
}

// HostResult is the outcome for one host.
type HostResult struct {
	Hostname string
	// Skipped is true when the run aborted before this host started.
	Skipped bool
	// Err is set when dialing or streaming failed (no summary reached).
	Err error
	// Ops holds the per-op results in apply order.
	Ops []proto.ApplyResult
	// Summary is the agent's aggregate for this host.
	Summary proto.ApplyResult
	// Changed, Failed and OK mirror the summary for convenience.
	Changed int
	Failed  int
	OK      int
}

// HasFailure reports whether this host failed (transport error or failed ops).
func (r HostResult) HasFailure() bool { return r.Err != nil || r.Failed > 0 }

// Report aggregates one run across all hosts.
type Report struct {
	// Results are in request order.
	Results []HostResult
	// Totals across hosts.
	Changed int
	Failed  int
	OK      int
	// Skipped counts hosts not run because the failure policy aborted.
	Skipped int
	// FailedHosts counts hosts that failed (transport or op failures).
	FailedHosts int
}

// Succeeded reports whether every host ran and succeeded.
func (r *Report) Succeeded() bool { return r.FailedHosts == 0 && r.Skipped == 0 }

// Err returns a summary error for an incomplete or failed run.
func (r *Report) Err() error {
	if r.Succeeded() {
		return nil
	}
	return fmt.Errorf("apply run incomplete: %d host(s) failed, %d skipped of %d",
		r.FailedHosts, r.Skipped, len(r.Results))
}

// Run applies the request across hosts with the given policy. It returns
// a report in request order; a non-nil error means the request itself was
// invalid (host failures are reported inside the Report).
func Run(ctx context.Context, req Request, opts Options) (*Report, error) {
	if len(req.Hosts) == 0 {
		return nil, errors.New("runner: no hosts to apply to")
	}
	if req.ServerPool == nil {
		return nil, errors.New("runner: server CA pool is required (mutual TLS)")
	}
	if req.Identity.Certificate.PrivateKey == nil {
		return nil, errors.New("runner: control client identity is required (mutual TLS)")
	}
	parallel := opts.Parallelism
	if parallel <= 0 {
		parallel = DefaultParallelism
	}
	if parallel > len(req.Hosts) {
		parallel = len(req.Hosts)
	}

	report := &Report{Results: make([]HostResult, len(req.Hosts))}
	var failedLive atomic.Int32

	jobs := make(chan int)
	var wg sync.WaitGroup
	for k := 0; k < parallel; k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				spec := req.Hosts[idx]
				if aborted(ctx, opts, &failedLive) {
					report.Results[idx] = HostResult{
						Hostname: spec.Target.Hostname,
						Skipped:  true,
					}
					continue
				}
				res := runHost(ctx, spec, req, opts)
				if res.Err != nil || res.Failed > 0 {
					failedLive.Add(1)
				}
				report.Results[idx] = res
			}
		}()
	}
	for k := range req.Hosts {
		jobs <- k
	}
	close(jobs)
	wg.Wait()

	// Aggregate totals single-threaded after the pool drains.
	for _, res := range report.Results {
		switch {
		case res.Skipped:
			report.Skipped++
		case res.HasFailure():
			report.FailedHosts++
		}
		report.Changed += res.Changed
		report.Failed += res.Failed
		report.OK += res.OK
	}
	return report, nil
}

// aborted reports whether the failure policy (or cancellation) stops new
// hosts from starting.
func aborted(ctx context.Context, opts Options, failed *atomic.Int32) bool {
	if ctx.Err() != nil {
		return true
	}
	if opts.MaxFailures < 0 {
		return false
	}
	return int(failed.Load()) > opts.MaxFailures
}

// runHost dials one agent and streams a full Apply run.
func runHost(ctx context.Context, spec HostSpec, req Request, opts Options) HostResult {
	res := HostResult{Hostname: spec.Target.Hostname}
	conn, err := proto.Dial(spec.Target.Addr, spec.Target.ServerName, req.Identity, req.ServerPool)
	if err != nil {
		res.Err = fmt.Errorf("dial %s (%s): %w", spec.Target.Hostname, spec.Target.Addr, err)
		return res
	}
	defer conn.Close()

	ops, summary, err := ApplyStream(ctx, conn, spec.Ops, opts.Check, opts.Timeout)
	res.Ops = ops
	res.Summary = summary
	if err != nil {
		res.Err = fmt.Errorf("apply on %s: %w", spec.Target.Hostname, err)
		return res
	}
	res.Changed = summary.Changes
	res.Failed = summary.Failures
	res.OK = summary.OK
	return res
}

// ApplyStream sends one Apply request and collects the streamed per-op
// results plus the final summary. The summary is the last result with
// Summary set.
func ApplyStream(ctx context.Context, conn *proto.Conn, ops []proto.Op, check bool, timeout time.Duration) ([]proto.ApplyResult, proto.ApplyResult, error) {
	params := proto.ApplyParams{Ops: ops, Check: check}
	if timeout > 0 {
		params.Timeout = timeout.Milliseconds()
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, proto.ApplyResult{}, fmt.Errorf("marshal apply params: %w", err)
	}
	id := fmt.Sprintf("apply-%d", time.Now().UnixNano())
	if err := conn.Send(proto.Request{ID: id, Method: proto.MethodApply, Params: raw}); err != nil {
		return nil, proto.ApplyResult{}, err
	}

	var results []proto.ApplyResult
	for {
		if err := ctx.Err(); err != nil {
			return results, proto.ApplyResult{}, err
		}
		var resp proto.Response
		if err := conn.Recv(&resp); err != nil {
			return results, proto.ApplyResult{}, err
		}
		if resp.ID != id {
			return results, proto.ApplyResult{}, fmt.Errorf("response id %q does not match request %q", resp.ID, id)
		}
		if resp.Error != nil {
			return results, proto.ApplyResult{}, resp.Error
		}
		var r proto.ApplyResult
		if err := json.Unmarshal(resp.Result, &r); err != nil {
			return results, proto.ApplyResult{}, fmt.Errorf("decode apply result: %w", err)
		}
		if r.Summary {
			return results, r, nil
		}
		results = append(results, r)
	}
}
