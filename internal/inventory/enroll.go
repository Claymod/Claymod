package inventory

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// EnrollHost atomically registers a host from a one-time enrollment
// token: the token is checked and consumed, a WireGuard IP is allocated
// and the host row is written in a single transaction. Hostname must
// match the token's binding. On success the returned Host has its WGIP
// filled.
//
// The agent's certificate (issued by the control CA before this call) is
// stored on the host row so revocation can record its serial later.
func (inv *Inventory) EnrollHost(token, hostname, publicKey, certPEM string) (*Host, error) {
	if hostname == "" {
		return nil, fmt.Errorf("hostname is required")
	}
	tx, err := inv.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin enroll: %w", err)
	}
	defer tx.Rollback()

	var boundHost, expiresAt, consumedAt string
	err = tx.QueryRow(
		`SELECT hostname, expires_at, consumed_at FROM tokens WHERE token = ?`,
		hashToken(token),
	).Scan(&boundHost, &expiresAt, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrTokenNotFound, token)
	}
	if err != nil {
		return nil, fmt.Errorf("lookup token: %w", err)
	}
	if _, err := checkToken(token, boundHost, expiresAt, consumedAt); err != nil {
		return nil, err
	}
	if boundHost != hostname {
		return nil, fmt.Errorf("token is bound to %q, not %q", boundHost, hostname)
	}

	// Consume the token first: within this transaction only one caller
	// can flip consumed_at, so a racing enrollment loses here.
	res, err := tx.Exec(
		`UPDATE tokens SET consumed_at = ? WHERE token = ? AND consumed_at = ''`,
		time.Now().UTC().Format(time.RFC3339Nano), hashToken(token),
	)
	if err != nil {
		return nil, fmt.Errorf("consume token: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, fmt.Errorf("%w: %s", ErrTokenUsed, token)
	}

	// Reject an already-enrolled hostname before burning the IP
	// allocation (same tx, so nothing is lost either way).
	var exists int
	if err := tx.QueryRow(`SELECT 1 FROM hosts WHERE hostname = ?`, hostname).Scan(&exists); err == nil {
		return nil, fmt.Errorf("%w: %s", ErrHostExists, hostname)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("check host exists: %w", err)
	}

	ip, err := inv.allocateInTx(tx, hostname)
	if err != nil {
		return nil, err
	}
	facts := "{}"
	_, err = tx.Exec(
		`INSERT INTO hosts (hostname, wg_ip, public_key, cert_pem, facts, last_seen)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		hostname, ip, publicKey, certPEM, facts,
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("%w: %s", classifyUnique(err), hostname)
		}
		return nil, fmt.Errorf("insert host: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit enroll: %w", err)
	}
	return &Host{
		Hostname:  hostname,
		WGIP:      ip,
		PublicKey: publicKey,
		CertPEM:   certPEM,
		Facts:     facts,
		LastSeen:  time.Now().UTC(),
	}, nil
}

// Revocation is a CRL-lite entry: a certificate serial that must no
// longer be trusted.
type Revocation struct {
	Serial    string
	Hostname  string
	RevokedAt time.Time
}

// AddRevocation records a revoked certificate serial (CRL-lite). The
// control side rejects hosts whose serial is recorded here.
func (inv *Inventory) AddRevocation(serial, hostname string) error {
	if serial == "" {
		return fmt.Errorf("serial is required")
	}
	_, err := inv.db.Exec(
		`INSERT OR REPLACE INTO revocations (serial, hostname, revoked_at) VALUES (?, ?, ?)`,
		serial, hostname, time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("insert revocation: %w", err)
	}
	return nil
}

// IsRevoked reports whether a certificate serial has been revoked.
func (inv *Inventory) IsRevoked(serial string) (bool, error) {
	var n int
	err := inv.db.QueryRow(`SELECT 1 FROM revocations WHERE serial = ?`, serial).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check revocation: %w", err)
	}
	return true, nil
}

// ListRevocations returns all revocation entries, newest first.
func (inv *Inventory) ListRevocations() ([]Revocation, error) {
	rows, err := inv.db.Query(
		`SELECT serial, hostname, revoked_at FROM revocations ORDER BY revoked_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list revocations: %w", err)
	}
	defer rows.Close()
	var out []Revocation
	for rows.Next() {
		var r Revocation
		var revokedAt string
		if err := rows.Scan(&r.Serial, &r.Hostname, &revokedAt); err != nil {
			return nil, err
		}
		r.RevokedAt, err = time.Parse(time.RFC3339Nano, revokedAt)
		if err != nil {
			return nil, fmt.Errorf("parse revoked_at: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
