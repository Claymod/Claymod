package proto

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// Handshake timeouts.
const (
	defaultDialTimeout    = 15 * time.Second
	defaultHandshakeFrame = 5 * time.Second
	// DefaultFrameTimeout bounds reading or writing one frame after the
	// handshake. Long applies stream frames inside this budget.
	DefaultFrameTimeout = 60 * time.Second
)

// Handshake is the first frame exchanged on every connection. Both sides
// send it and refuse peers speaking a different version.
type Handshake struct {
	Version uint8  `json:"version"`
	Role    string `json:"role"`
	Agent   string `json:"agent,omitempty"`
}

// Roles in the handshake.
const (
	RoleServer = "server"
	RoleAgent  = "agent"
)

// Conn wraps a TLS connection with the framed protocol: one handshake,
// then Request/Response frames with per-frame deadlines.
type Conn struct {
	tls     *tls.Conn
	peer    Handshake
	timeout time.Duration
}

// Listen opens a mutual-TLS listener on addr using the given identity and
// CA pool for client verification. The client certificate CN must match a
// known hostname (checked by the caller, usually the agent).
func Listen(addr string, id Identity, clientPool *x509.CertPool) (net.Listener, error) {
	cfg, err := serverTLSConfig(id, clientPool)
	if err != nil {
		return nil, err
	}
	ln, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("proto: listen on %s: %w", addr, err)
	}
	return ln, nil
}

// Dial connects to addr over mutual TLS and completes the handshake as the
// client (the control server role). The server certificate is verified
// against serverPool (and its SAN must match addr's host, or serverName
// when given).
func Dial(addr, serverName string, id Identity, serverPool *x509.CertPool) (*Conn, error) {
	cfg := &tls.Config{
		RootCAs:    serverPool,
		ServerName: serverName,
		MinVersion: tls.VersionTLS13,
	}
	// An empty Identity presents no client certificate (used by negative
	// TLS probes against agents that require mutual TLS).
	if id.Certificate.PrivateKey != nil {
		cfg.Certificates = []tls.Certificate{id.Certificate}
	}
	d := net.Dialer{Timeout: defaultDialTimeout}
	raw, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("proto: dial %s: %w", addr, err)
	}
	tconn := tls.Client(raw, cfg)
	if err := tconn.SetDeadline(time.Now().Add(defaultDialTimeout)); err != nil {
		raw.Close()
		return nil, err
	}
	if err := tconn.Handshake(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("proto: tls handshake with %s: %w", addr, err)
	}
	if err := tconn.SetDeadline(time.Time{}); err != nil {
		raw.Close()
		return nil, err
	}
	conn := &Conn{tls: tconn, timeout: DefaultFrameTimeout}
	if err := conn.clientHandshake(); err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

// Server upgrades an accepted connection and completes the handshake as
// the server role. It returns an error for peers speaking another version.
func Server(raw net.Conn, timeout time.Duration) (*Conn, error) {
	tconn, ok := raw.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("proto: server expects a *tls.Conn, got %T", raw)
	}
	if timeout <= 0 {
		timeout = DefaultFrameTimeout
	}
	conn := &Conn{tls: tconn, timeout: timeout}
	if err := conn.serverHandshake(); err != nil {
		return nil, err
	}
	return conn, nil
}

// Peer returns the handshake received from the remote side.
func (c *Conn) Peer() Handshake { return c.peer }

// PeerSerial returns the hex serial of the peer's leaf certificate and
// whether one was presented. The runner uses it to enforce CRL-lite
// revocation before any ops flow.
func (c *Conn) PeerSerial() (string, bool) {
	certs := c.tls.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", false
	}
	return certs[0].SerialNumber.String(), true
}

// Send marshals v as a frame.
func (c *Conn) Send(v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("proto: marshal frame: %w", err)
	}
	if err := c.tls.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return err
	}
	return writeFrame(c.tls, payload)
}

// Recv reads one frame and unmarshals it into v.
func (c *Conn) Recv(v any) error {
	if err := c.tls.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return err
	}
	payload, err := readFrame(c.tls)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(payload, v); err != nil {
		return fmt.Errorf("proto: unmarshal frame: %w", err)
	}
	return nil
}

// Call sends a request and waits for the matching response. It is the
// client-side convenience used by the runner.
func (c *Conn) Call(req Request, result any) (*Error, error) {
	if err := c.Send(req); err != nil {
		return nil, err
	}
	var resp Response
	if err := c.Recv(&resp); err != nil {
		return nil, err
	}
	if resp.ID != req.ID {
		return nil, fmt.Errorf("proto: response id %q does not match request %q", resp.ID, req.ID)
	}
	if resp.Error != nil {
		return resp.Error, nil
	}
	if result != nil && len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, result); err != nil {
			return nil, fmt.Errorf("proto: unmarshal result: %w", err)
		}
	}
	return nil, nil
}

// Close closes the underlying connection.
func (c *Conn) Close() error { return c.tls.Close() }

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr { return c.tls.RemoteAddr() }

// clientHandshake sends the client handshake and reads the peer's
// response. Both frames travel under the handshake deadline (not the
// per-frame timeout), so a stalled peer cannot hold the handshake open.
func (c *Conn) clientHandshake() error {
	if err := c.setHandshakeDeadline(); err != nil {
		return err
	}
	if err := c.sendHandshake(Handshake{Version: Version, Role: RoleServer}); err != nil {
		return fmt.Errorf("proto: send handshake: %w", err)
	}
	peer, err := c.recvHandshake()
	if err != nil {
		return fmt.Errorf("proto: read handshake: %w", err)
	}
	return c.checkPeer(peer)
}

// serverHandshake reads the client's handshake and answers it. Both frames
// travel under the handshake deadline.
func (c *Conn) serverHandshake() error {
	if err := c.setHandshakeDeadline(); err != nil {
		return err
	}
	peer, err := c.recvHandshake()
	if err != nil {
		return fmt.Errorf("proto: read handshake: %w", err)
	}
	if err := c.checkPeer(peer); err != nil {
		return err
	}
	if err := c.sendHandshake(Handshake{Version: Version, Role: RoleAgent}); err != nil {
		return fmt.Errorf("proto: send handshake: %w", err)
	}
	return nil
}

// sendHandshake writes one handshake frame using raw frame I/O; the
// deadline was set by setHandshakeDeadline and is not reset here.
func (c *Conn) sendHandshake(hs Handshake) error {
	payload, err := json.Marshal(hs)
	if err != nil {
		return fmt.Errorf("proto: marshal handshake: %w", err)
	}
	return writeFrame(c.tls, payload)
}

// recvHandshake reads one handshake frame using raw frame I/O; the
// deadline was set by setHandshakeDeadline and is not reset here.
func (c *Conn) recvHandshake() (Handshake, error) {
	payload, err := readFrame(c.tls)
	if err != nil {
		return Handshake{}, err
	}
	var hs Handshake
	if err := json.Unmarshal(payload, &hs); err != nil {
		return Handshake{}, fmt.Errorf("proto: unmarshal handshake: %w", err)
	}
	return hs, nil
}

func (c *Conn) setHandshakeDeadline() error {
	return c.tls.SetDeadline(time.Now().Add(defaultHandshakeFrame))
}

func (c *Conn) checkPeer(peer Handshake) error {
	c.tls.SetDeadline(time.Time{})
	if peer.Version != Version {
		return fmt.Errorf("proto: peer protocol version %d, want %d", peer.Version, Version)
	}
	c.peer = peer
	return nil
}

// ErrServerClosed is returned by Accept loops after Close.
var ErrServerClosed = errors.New("proto: server closed")

func serverTLSConfig(id Identity, clientPool *x509.CertPool) (*tls.Config, error) {
	if clientPool == nil {
		return nil, errors.New("proto: client CA pool is required (mutual TLS)")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{id.Certificate},
		ClientCAs:    clientPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// Identity is a loaded TLS certificate/key pair.
type Identity struct {
	Certificate tls.Certificate
}

// LoadIdentity parses a PEM certificate/key pair into a TLS identity.
func LoadIdentity(certPEM, keyPEM []byte) (Identity, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return Identity{}, fmt.Errorf("proto: load identity: %w", err)
	}
	return Identity{Certificate: cert}, nil
}

// CertPoolFromPEM builds a certificate pool from PEM data.
func CertPoolFromPEM(pemBytes []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("proto: no certificates found in PEM data")
	}
	return pool, nil
}

// PeerCommonName returns the verified CN of the remote client certificate.
// It completes the (lazy) TLS handshake first, so it is safe on a freshly
// accepted connection that has not done I/O yet. Agents use it to
// authorize the caller. It returns an error for non-TLS connections and
// for peers without a verified certificate.
func PeerCommonName(raw net.Conn) (string, error) {
	tconn, ok := raw.(*tls.Conn)
	if !ok {
		return "", errors.New("proto: not a TLS connection")
	}
	if err := tconn.Handshake(); err != nil {
		return "", fmt.Errorf("proto: tls handshake: %w", err)
	}
	for _, cert := range tconn.ConnectionState().PeerCertificates {
		return cert.Subject.CommonName, nil
	}
	return "", errors.New("proto: no verified peer certificate")
}
