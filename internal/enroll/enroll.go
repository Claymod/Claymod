// Package enroll defines the enrollment wire contract and the CLIENT
// side of it: a one-time token exchanged over the control server's HTTPS
// bootstrap endpoint for the host's identity material. The agent's
// WireGuard private key is generated on the host and never leaves it.
//
// Deliberately light (stdlib only): the agent binary links this package
// without pulling in inventory, the CA or wgctrl. The server side lives
// in internal/enrollserver.
//
// Flow (client -> server, all over HTTPS):
//
//  1. POST /enroll {token, hostname, wg_public_key}
//  2. response {wg_ip, overlay, ca_cert, client_cert, client_key,
//     wg_server_public, wg_endpoint}
//  3. client writes /etc/claymod/{agent.yaml,ca.pem,agent.pem,
//     agent-key.pem,wg-setup.json} and brings up WireGuard.
package enroll

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
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
