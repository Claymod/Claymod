// Package inventory persists hosts, enrollment tokens and WireGuard IP
// allocations in SQLite. The hostname is the primary key; IPAM allocations
// are durable rows (not in-memory state) so restarts never lose them.
package inventory

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// Sentinel errors returned by the inventory.
var (
	ErrNotFound      = errors.New("host not found")
	ErrHostExists    = errors.New("host already exists")
	ErrIPInUse       = errors.New("ip already allocated")
	ErrIPReserved    = errors.New("ip is reserved for the control server")
	ErrIPOutOfRange  = errors.New("ip outside agent network")
	ErrIPExhausted   = errors.New("no free ip in agent network")
	ErrTokenNotFound = errors.New("token not found")
	ErrTokenExpired  = errors.New("token expired")
	ErrTokenUsed     = errors.New("token already used")
)

// Host is an enrolled host record. WGIP is allocated by IPAM on add.
type Host struct {
	Hostname  string
	WGIP      string
	PublicKey string
	CertPEM   string
	Facts     string // JSON blob, filled by the agent over time
	LastSeen  time.Time
}

// Inventory is the SQLite-backed host database.
type Inventory struct {
	db   *sql.DB
	ipam *ipam
}

// Open opens (creating when needed) the inventory database at path and
// prepares it for the given agent network CIDR (IPv4 only).
func Open(path, agentNetwork string) (*Inventory, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open inventory db: %w", err)
	}
	// SQLite is single-writer; cap the pool to one connection to avoid
	// "database is locked" churn, and enable WAL for concurrent readers.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable wal: %w", err)
	}
	if _, err := db.Exec(`PRAGMA foreign_keys=ON;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}
	ippool, err := newIPAM(agentNetwork)
	if err != nil {
		db.Close()
		return nil, err
	}
	inv := &Inventory{db: db, ipam: ippool}
	if err := inv.createTables(); err != nil {
		db.Close()
		return nil, err
	}
	return inv, nil
}

// Close releases the database handle.
func (inv *Inventory) Close() error {
	return inv.db.Close()
}

// Overlay returns the agent network CIDR the inventory allocates from.
func (inv *Inventory) Overlay() string {
	return inv.ipam.network.String()
}

// ServerIP returns the overlay address reserved for the control server
// (network base + 1). It is never allocated to a host.
func (inv *Inventory) ServerIP() string {
	return inv.ipam.serverAddr().String()
}

// IsServerIP reports whether ip is the reserved control-server address.
func (inv *Inventory) IsServerIP(ip string) bool {
	return inv.ipam.isServerAddr(ip)
}

func (inv *Inventory) createTables() error {
	schema := `
CREATE TABLE IF NOT EXISTS hosts (
  hostname   TEXT PRIMARY KEY,
  wg_ip      TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL DEFAULT '',
  cert_pem   TEXT NOT NULL DEFAULT '',
  facts      TEXT NOT NULL DEFAULT '{}',
  last_seen  TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS tokens (
  token      TEXT PRIMARY KEY,
  hostname   TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS ip_allocations (
  ip          TEXT PRIMARY KEY,
  hostname    TEXT NOT NULL UNIQUE,
  allocated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS revocations (
  serial     TEXT PRIMARY KEY,
  hostname   TEXT NOT NULL,
  revoked_at TEXT NOT NULL
);`
	if _, err := inv.db.Exec(schema); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}
	return nil
}

// AddHost registers a host and allocates its WireGuard IP. When h.WGIP is
// empty the next free IP is allocated from the agent network; otherwise the
// given IP must be in range and unallocated. The allocation and the host
// row are committed in one transaction. On return h.WGIP is filled.
func (inv *Inventory) AddHost(h *Host) error {
	if h.Hostname == "" {
		return fmt.Errorf("hostname is required")
	}
	tx, err := inv.db.Begin()
	if err != nil {
		return fmt.Errorf("begin add host: %w", err)
	}
	defer tx.Rollback()

	var exists int
	if err := tx.QueryRow(`SELECT 1 FROM hosts WHERE hostname = ?`, h.Hostname).Scan(&exists); err == nil {
		return fmt.Errorf("%w: %s", ErrHostExists, h.Hostname)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check host exists: %w", err)
	}

	ip := h.WGIP
	if ip == "" {
		allocated, err := inv.allocateInTx(tx, h.Hostname)
		if err != nil {
			return err
		}
		ip = allocated
	} else {
		if inv.ipam.isServerAddr(ip) {
			return fmt.Errorf("%w: %s", ErrIPReserved, ip)
		}
		if !inv.ipam.inRange(ip) {
			return fmt.Errorf("%w: %s", ErrIPOutOfRange, ip)
		}
		if err := inv.reserveInTx(tx, ip, h.Hostname); err != nil {
			return err
		}
	}

	lastSeen := ""
	if !h.LastSeen.IsZero() {
		lastSeen = h.LastSeen.UTC().Format(time.RFC3339Nano)
	}
	facts := h.Facts
	if facts == "" {
		facts = "{}"
	}
	_, err = tx.Exec(
		`INSERT INTO hosts (hostname, wg_ip, public_key, cert_pem, facts, last_seen)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		h.Hostname, ip, h.PublicKey, h.CertPEM, facts, lastSeen,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: %s", classifyUnique(err), h.Hostname)
		}
		return fmt.Errorf("insert host: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit add host: %w", err)
	}
	h.WGIP = ip
	return nil
}

// RemoveHost deletes a host and frees its IP allocation in one transaction.
// The freed IP is immediately reusable by a later AddHost.
func (inv *Inventory) RemoveHost(hostname string) error {
	tx, err := inv.db.Begin()
	if err != nil {
		return fmt.Errorf("begin remove host: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.Exec(`DELETE FROM hosts WHERE hostname = ?`, hostname)
	if err != nil {
		return fmt.Errorf("delete host: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, hostname)
	}
	if _, err := tx.Exec(`DELETE FROM ip_allocations WHERE hostname = ?`, hostname); err != nil {
		return fmt.Errorf("free ip: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit remove host: %w", err)
	}
	return nil
}

// GetHost returns the host with the given hostname.
func (inv *Inventory) GetHost(hostname string) (*Host, error) {
	row := inv.db.QueryRow(
		`SELECT hostname, wg_ip, public_key, cert_pem, facts, last_seen
		 FROM hosts WHERE hostname = ?`, hostname)
	return scanHost(row)
}

// ListHosts returns all hosts ordered by hostname.
func (inv *Inventory) ListHosts() ([]*Host, error) {
	rows, err := inv.db.Query(
		`SELECT hostname, wg_ip, public_key, cert_pem, facts, last_seen
		 FROM hosts ORDER BY hostname`)
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}
	defer rows.Close()
	var hosts []*Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, h)
	}
	return hosts, rows.Err()
}

// UpdateHost refreshes mutable host fields (public key, certificate,
// facts, last-seen). Hostname and WGIP are immutable.
func (inv *Inventory) UpdateHost(h *Host) error {
	res, err := inv.db.Exec(
		`UPDATE hosts SET public_key = ?, cert_pem = ?, facts = ?, last_seen = ?
		 WHERE hostname = ?`,
		h.PublicKey, h.CertPEM, h.Facts,
		h.LastSeen.UTC().Format(time.RFC3339Nano), h.Hostname,
	)
	if err != nil {
		return fmt.Errorf("update host: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, h.Hostname)
	}
	return nil
}

// hashToken returns the hex SHA-256 of an enrollment token: tokens are
// stored ONLY as digests, so a stolen inventory.db grants nothing.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// StoreToken records a one-time enrollment token for hostname expiring
// at expiresAt. Only the token DIGEST is stored.
func (inv *Inventory) StoreToken(token, hostname string, expiresAt time.Time) error {
	if token == "" {
		return fmt.Errorf("token is required")
	}
	_, err := inv.db.Exec(
		`INSERT INTO tokens (token, hostname, created_at, expires_at)
		 VALUES (?, ?, ?, ?)`,
		hashToken(token), hostname,
		time.Now().UTC().Format(time.RFC3339Nano),
		expiresAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("insert token: %w", err)
	}
	return nil
}

// ValidateToken returns the hostname a token was issued for, without
// consuming it. It fails for unknown, expired or already-used tokens.
func (inv *Inventory) ValidateToken(token string) (string, error) {
	var hostname, expiresAt, consumedAt string
	err := inv.db.QueryRow(
		`SELECT hostname, expires_at, consumed_at FROM tokens WHERE token = ?`,
		hashToken(token),
	).Scan(&hostname, &expiresAt, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("%w: %s", ErrTokenNotFound, token)
	}
	if err != nil {
		return "", fmt.Errorf("lookup token: %w", err)
	}
	return checkToken(token, hostname, expiresAt, consumedAt)
}

// ConsumeToken validates and marks a token used in one transaction. This is
// the atomic check-and-consume used during enrollment.
func (inv *Inventory) ConsumeToken(token string) (string, error) {
	tx, err := inv.db.Begin()
	if err != nil {
		return "", fmt.Errorf("begin consume token: %w", err)
	}
	defer tx.Rollback()

	var hostname, expiresAt, consumedAt string
	err = tx.QueryRow(
		`SELECT hostname, expires_at, consumed_at FROM tokens WHERE token = ?`,
		hashToken(token),
	).Scan(&hostname, &expiresAt, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("%w: %s", ErrTokenNotFound, token)
	}
	if err != nil {
		return "", fmt.Errorf("lookup token: %w", err)
	}
	host, err := checkToken(token, hostname, expiresAt, consumedAt)
	if err != nil {
		return "", err
	}
	_, err = tx.Exec(
		`UPDATE tokens SET consumed_at = ? WHERE token = ? AND consumed_at = ''`,
		time.Now().UTC().Format(time.RFC3339Nano), hashToken(token),
	)
	if err != nil {
		return "", fmt.Errorf("consume token: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit consume token: %w", err)
	}
	return host, nil
}

// AllocatedIPs returns the set of currently allocated IPs (for tests and
// operator tooling).
func (inv *Inventory) AllocatedIPs() ([]string, error) {
	rows, err := inv.db.Query(`SELECT ip FROM ip_allocations ORDER BY ip`)
	if err != nil {
		return nil, fmt.Errorf("list allocations: %w", err)
	}
	defer rows.Close()
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, rows.Err()
}

func (inv *Inventory) allocateInTx(tx *sql.Tx, hostname string) (string, error) {
	rows, err := tx.Query(`SELECT ip FROM ip_allocations`)
	if err != nil {
		return "", fmt.Errorf("read allocations: %w", err)
	}
	used := map[string]bool{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			rows.Close()
			return "", err
		}
		used[ip] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", err
	}
	ip := inv.ipam.nextFree(used)
	if ip == "" {
		return "", ErrIPExhausted
	}
	if err := inv.reserveInTx(tx, ip, hostname); err != nil {
		return "", err
	}
	return ip, nil
}

func (inv *Inventory) reserveInTx(tx *sql.Tx, ip, hostname string) error {
	_, err := tx.Exec(
		`INSERT INTO ip_allocations (ip, hostname, allocated_at) VALUES (?, ?, ?)`,
		ip, hostname, time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		if isUniqueViolation(err) {
			cls := classifyUnique(err)
			if errors.Is(cls, ErrHostExists) {
				return fmt.Errorf("%w: %s", cls, hostname)
			}
			return fmt.Errorf("%w: %s", cls, ip)
		}
		return fmt.Errorf("insert ip allocation: %w", err)
	}
	return nil
}

func scanHost(row interface{ Scan(...any) error }) (*Host, error) {
	var h Host
	var lastSeen string
	err := row.Scan(&h.Hostname, &h.WGIP, &h.PublicKey, &h.CertPEM, &h.Facts, &lastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan host: %w", err)
	}
	if lastSeen != "" {
		h.LastSeen, err = time.Parse(time.RFC3339Nano, lastSeen)
		if err != nil {
			return nil, fmt.Errorf("parse last_seen: %w", err)
		}
	}
	return &h, nil
}

func checkToken(token, hostname, expiresAt, consumedAt string) (string, error) {
	if consumedAt != "" {
		return "", fmt.Errorf("%w: %s", ErrTokenUsed, token)
	}
	exp, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return "", fmt.Errorf("parse token expiry: %w", err)
	}
	if time.Now().After(exp) {
		return "", fmt.Errorf("%w: %s", ErrTokenExpired, token)
	}
	return hostname, nil
}

func isUniqueViolation(err error) bool {
	// modernc.org/sqlite surfaces constraint failures with this text.
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// classifyUnique maps a UNIQUE violation to the right sentinel: the
// ip_allocations table is unique on both ip and hostname.
func classifyUnique(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "ip_allocations.hostname") || strings.Contains(msg, "hosts.hostname"):
		return ErrHostExists
	case strings.Contains(msg, "ip_allocations.ip") || strings.Contains(msg, "hosts.wg_ip"):
		return ErrIPInUse
	default:
		return err
	}
}
