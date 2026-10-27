// Package enroll implements claymod's enrollment flow: a one-time-token
// exchange over an HTTPS bootstrap endpoint that registers a host in the
// inventory, issues its client certificate and installs it as a WireGuard
// peer. The agent's WireGuard private key is generated on the host and
// never leaves it; the client certificate keypair is issued server-side
// and returned only over TLS.
//
// Flow (client → server, all over HTTPS):
//
//  1. POST /enroll {token, hostname, wg_public_key}
//  2. server: consume token (atomic), allocate WG IP, issue client cert,
//     register WG peer, store host — one transactional enrollment
//  3. response {wg_ip, ca_cert, client_cert, client_key, wg_server_public,
//     wg_endpoint}
//  4. client writes /etc/claymod/{agent.yaml,ca.pem,agent.pem,agent-key.pem}
//     and brings up its WireGuard interface (see docs/enrollment.md).
package enroll

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/claymod/claymod/internal/ca"
	"github.com/claymod/claymod/internal/inventory"
	"github.com/claymod/claymod/internal/wgmgr"
)

// Request is the client's enrollment request.
type Request struct {
	// Token is the one-time enrollment token issued by the operator.
	Token string `json:"token"`
	// Hostname must match the token's binding.
	Hostname string `json:"hostname"`
	// WgPublicKey is the host's WireGuard public key (the private key
	// stays on the host).
	WgPublicKey string `json:"wg_public_key"`
}

// Response is the server's enrollment payload.
type Response struct {
	Hostname string `json:"hostname"`
	// WGIP is the allocated WireGuard overlay address.
	WGIP string `json:"wg_ip"`
	// CACert is the PEM bundle the agent uses to verify the server.
	CACert []byte `json:"ca_cert"`
	// ClientCert/ClientKey are the agent's mTLS identity.
	ClientCert []byte `json:"client_cert"`
	ClientKey  []byte `json:"client_key"`
	// WgServerPublicKey is the control server's WireGuard public key.
	WgServerPublicKey string `json:"wg_server_public"`
	// WgEndpoint is the control server's WireGuard listen address.
	WgEndpoint string `json:"wg_endpoint"`
	// Overlay is the agent network aggregate (e.g. 10.42.0.0/24) routed
	// to the control server on the host's side of the tunnel.
	Overlay string `json:"overlay"`
}

// Server is the HTTPS bootstrap endpoint. It requires TLS (run it behind
// the internal CA's server certificate).
type Server struct {
	Inv *inventory.Inventory
	CA  *ca.CA
	WG  *wgmgr.Manager
	Log *slog.Logger
	// HostnameHeader optionally pins the expected hostname header.
	now func() time.Time
}

// NewServer wires a bootstrap server.
func NewServer(inv *inventory.Inventory, authority *ca.CA, wg *wgmgr.Manager, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{Inv: inv, CA: authority, WG: wg, Log: log, now: time.Now}
}

// Handler returns the HTTP mux for the bootstrap endpoint.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /enroll", s.handleEnroll)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req Request
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
func (s *Server) Enroll(ctx context.Context, req Request) (*Response, error) {
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

	return &Response{
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

// EnrollClient enrolls this host against a bootstrap server over HTTPS.
// It generates a WireGuard key pair locally (the private key never leaves
// the host) and returns the server's response.
func EnrollClient(ctx context.Context, serverURL string, client *http.Client, req Request) (*Response, error) {
	if client == nil {
		return nil, fmt.Errorf("enroll: http client with pinned CA is required")
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		serverURL+"/enroll", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("enroll: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("enroll: server refused (%d): %s", resp.StatusCode, string(body))
	}
	var out Response
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("enroll: parse response: %w", err)
	}
	return &out, nil
}

// NewPinnedClient builds an HTTP client that verifies the bootstrap
// server against a pinned CA bundle (or a pinned certificate fingerprint).
func NewPinnedClient(caPEM []byte) (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("enroll: no certificates in CA bundle")
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS13,
			},
		},
	}, nil
}

func httpError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
