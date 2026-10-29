// Package enrollserver is the CONTROL-SIDE enrollment endpoint: it
// consumes one-time tokens, issues agent identities from the internal
// CA, registers WireGuard peers and stores hosts. Separate from the
// light client contract (internal/enroll) so the agent binary never
// links inventory, the CA or wgctrl.
package enrollserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/claymod/claymod/internal/ca"
	"github.com/claymod/claymod/internal/enroll"
	"github.com/claymod/claymod/internal/inventory"
	"github.com/claymod/claymod/internal/wgmanager"
)

// Server is the HTTPS bootstrap endpoint. It requires TLS (run it behind
// the internal CA's server certificate).
type Server struct {
	Inv *inventory.Inventory
	CA  *ca.CA
	WG  *wgmanager.Manager
	Log *slog.Logger
	// AgentBinDir holds claymod-agent binaries served to hosts during
	// bootstrap (GET /agent/{goos}/{goarch}), air-gap friendly. Empty
	// disables the endpoint. Files are named claymod-agent-<goos>-<goarch>.
	AgentBinDir string
	// HostnameHeader optionally pins the expected hostname header.
	now func() time.Time
}

// NewServer wires a bootstrap server.
func NewServer(inv *inventory.Inventory, authority *ca.CA, wg *wgmanager.Manager, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{Inv: inv, CA: authority, WG: wg, Log: log, now: time.Now}
}

// Handler returns the HTTP mux for the bootstrap endpoint.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /enroll", s.handleEnroll)
	mux.HandleFunc("GET /agent/", s.handleAgentDownload)
	mux.HandleFunc("/ca.pem", s.handleCA)
	mux.HandleFunc("/enroll.sh", s.handleEnrollScript)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req enroll.Request
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		httpError(w, http.StatusBadRequest, "read request: "+err.Error())
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		httpError(w, http.StatusBadRequest, "parse request: "+err.Error())
		return
	}
	if req.Token == "" || req.Hostname == "" || req.WgPublicKey == "" {
		httpError(w, http.StatusBadRequest, "token, hostname and wg_public_key are required")
		return
	}

	resp, err := s.Enroll(r.Context(), req)
	if err != nil {
		s.Log.Warn("enrollment refused",
			"hostname", req.Hostname, "remote", r.RemoteAddr, "err", err)
		status := http.StatusBadRequest
		switch {
		case err == inventory.ErrTokenNotFound || err == inventory.ErrTokenExpired ||
			err == inventory.ErrTokenUsed || err == inventory.ErrHostExists:
			status = http.StatusUnauthorized
		}
		httpError(w, status, err.Error())
		return
	}
	s.Log.Info("host enrolled",
		"hostname", resp.Hostname, "wg_ip", resp.WGIP, "remote", r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// Enroll performs the full enrollment: consume the token, issue the
// client certificate, register the WireGuard peer and store the host.
// The inventory enrollment is atomic (token + IP + host row in one tx).
func (s *Server) Enroll(ctx context.Context, req enroll.Request) (*enroll.Response, error) {
	// Issue the agent's identity BEFORE the inventory transaction so a
	// CA failure never burns a token. Two details are load-bearing:
	//
	//   - DNSNames carries the hostname: the runner dials the agent with
	//     ServerName=hostname, and Go (>=1.15) ignores the CN for
	//     hostname verification.
	//   - Usage is ServerAuth, not ClientAuth: the agent LISTENS (it is
	//     the TLS server), the control server dials. The agent's
	//     certificate is verified as a server certificate by the runner.
	certPEM, keyPEM, err := s.CA.IssueCert(ca.IssueOptions{
		CommonName: req.Hostname,
		Usage:      ca.UsageServer,
		DNSNames:   []string{req.Hostname},
		Validity:   365 * 24 * time.Hour,
	})
	if err != nil {
		return nil, fmt.Errorf("issue client certificate: %w", err)
	}

	host, err := s.Inv.EnrollHost(req.Token, req.Hostname, req.WgPublicKey, string(certPEM))
	if err != nil {
		return nil, err
	}

	// Install the WireGuard peer. Failure here rolls the host back so the
	// inventory and the overlay never disagree.
	if err := s.WG.Enroll(req.Hostname, req.WgPublicKey, host.WGIP); err != nil {
		// Best-effort cleanup: free the IP and drop the host row.
		if rmErr := s.Inv.RemoveHost(req.Hostname); rmErr != nil {
			s.Log.Error("rollback after wg failure", "hostname", req.Hostname, "err", rmErr)
		}
		return nil, fmt.Errorf("register wireguard peer: %w", err)
	}

	return &enroll.Response{
		Hostname:          host.Hostname,
		WGIP:              host.WGIP,
		CACert:            s.CA.CertPEM(),
		ClientCert:        certPEM,
		ClientKey:         keyPEM,
		WgServerPublicKey: s.WG.ControlKeys.Public,
		WgEndpoint:        s.WG.ServerEndpoint,
		Overlay:           s.Inv.Overlay(),
	}, nil
}

// Revoke performs the full revocation for a host: remove the WireGuard
// peer, record the certificate serial (CRL-lite) and drop the host row
// (freeing its IP).
func (s *Server) Revoke(hostname string) error {
	host, err := s.Inv.GetHost(hostname)
	if err != nil {
		return err
	}
	// Record the certificate serial before removing the row (the serial
	// is derived from the stored PEM).
	if host.CertPEM != "" {
		if cert, err := ca.ParseCertPEM([]byte(host.CertPEM)); err == nil {
			if err := s.Inv.AddRevocation(cert.SerialNumber.String(), hostname); err != nil {
				return err
			}
		}
	}
	if err := s.WG.Revoke(host.PublicKey); err != nil {
		return err
	}
	if err := s.Inv.RemoveHost(hostname); err != nil {
		return err
	}
	// The config file's peer list comes from the inventory: refresh it
	// now that the host row is gone (WG.Revoke persisted too early — the
	// row was still there at that point).
	return s.WG.RefreshConf()
}

// handleAgentDownload serves the agent binary (and its .sha256 digest)
// for GET /agent/<goos>/<goarch> — the air-gap bootstrap flow: the host
// fetches its agent over the same pinned TLS channel as enrollment.
// The binary carries no secrets; integrity comes from the .sha256 digest
// (compare with the one `claymod serve` logs at startup).
func (s *Server) handleAgentDownload(w http.ResponseWriter, r *http.Request) {
	if s.AgentBinDir == "" {
		httpError(w, http.StatusNotFound, "agent binaries not offered (serve --agent-bin-dir)")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/agent/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		httpError(w, http.StatusNotFound, "want /agent/<goos>/<goarch>")
		return
	}
	goos, goarch := parts[0], parts[1]
	wantDigest := strings.HasSuffix(goarch, ".sha256")
	if wantDigest {
		goarch = strings.TrimSuffix(goarch, ".sha256")
	}
	if !knownPlatforms(goos + "/" + goarch) {
		httpError(w, http.StatusNotFound, fmt.Sprintf("no agent for %s/%s", goos, goarch))
		return
	}
	path := filepath.Join(s.AgentBinDir, "claymod-agent-"+goos+"-"+goarch)
	data, err := os.ReadFile(path)
	if err != nil {
		httpError(w, http.StatusNotFound,
			fmt.Sprintf("no agent binary for %s/%s on the server: drop the release asset claymod-agent-%s-%s into --agent-bin-dir", goos, goarch, goos, goarch))
		return
	}
	if wantDigest {
		sum := sha256.Sum256(data)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "%x\n", sum)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

// knownPlatforms lists the GOOS/GOARCH pairs claymod agents are built
// for (see `make agents`).
func knownPlatforms(pair string) bool {
	switch pair {
	case "linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64":
		return true
	}
	return false
}

// AgentDigests returns "<goos>-<goarch> <sha256>" lines for every agent
// binary in dir (serve logs these at startup for out-of-band
// verification).
func AgentDigests(dir string) ([]string, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "claymod-agent-") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		out = append(out, fmt.Sprintf("%s %x",
			strings.TrimPrefix(e.Name(), "claymod-agent-"), sum))
	}
	sort.Strings(out)
	return out, nil
}

func httpError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
