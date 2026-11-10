// Package identitypg implements persistent Gateway identity, OIDC login flows,
// and revocable browser sessions. It is NOT an Order Service data adapter.
package identitypg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/MeowMeowOrganization/meow-gateway/internal/auth"
	"github.com/MeowMeowOrganization/meow-gateway/internal/browserauth"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type Store struct{ db *sql.DB }

func Open(ctx context.Context, dsn string) (*Store, error) {
	if dsn == "" {
		return nil, errors.New("identity database DSN is missing")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open identity database: %w", err)
	}
	db.SetMaxOpenConns(12)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(30 * time.Minute)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("identity database unavailable: %w", err)
	}
	// Fail startup rather than treating a missing migration as an empty identity registry.
	var initialized bool
	if err = db.QueryRowContext(ctx, `SELECT to_regclass('gateway_identity.browser_sessions') IS NOT NULL AND to_regclass('gateway_identity.account_memberships') IS NOT NULL AND to_regclass('gateway_identity.login_flows') IS NOT NULL`).Scan(&initialized); err != nil || !initialized {
		db.Close()
		return nil, errors.New("gateway identity schema migration is required")
	}
	return &Store{db: db}, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) SaveFlow(ctx context.Context, k [32]byte, f browserauth.Flow) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO gateway_identity.login_flows(state_hash,nonce,pkce_verifier,expires_at) VALUES($1,$2,$3,$4)`, k[:], f.Nonce, f.Verifier, f.ExpiresAt)
	return err
}
func (s *Store) TakeFlow(ctx context.Context, k [32]byte) (browserauth.Flow, error) {
	var f browserauth.Flow
	err := s.db.QueryRowContext(ctx, `DELETE FROM gateway_identity.login_flows WHERE state_hash=$1 RETURNING nonce,pkce_verifier,expires_at`, k[:]).Scan(&f.Nonce, &f.Verifier, &f.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return browserauth.Flow{}, browserauth.ErrNotFound
	}
	return f, err
}

// No JIT auto-provisioning, no linking by email, no selection of an arbitrary
// first account. A user with multiple active memberships cannot log in yet.
func (s *Store) ResolveIdentity(ctx context.Context, issuer, sub string) (browserauth.Identity, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT i.identity_id::text,m.account_id
 FROM gateway_identity.oidc_identities i
 JOIN gateway_identity.users u ON u.user_id=i.user_id AND u.enabled
 JOIN gateway_identity.account_memberships m ON m.user_id=u.user_id AND m.enabled
 WHERE i.issuer=$1 AND i.subject=$2 ORDER BY m.account_id LIMIT 2`, issuer, sub)
	if err != nil {
		return browserauth.Identity{}, err
	}
	defer rows.Close()
	var id browserauth.Identity
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return id, err
		}
		return id, browserauth.ErrNotFound
	}
	if err := rows.Scan(&id.IdentityID, &id.AccountID); err != nil {
		return browserauth.Identity{}, err
	}
	if rows.Next() {
		return browserauth.Identity{}, errors.New("ambiguous account membership: refuse automatic account selection")
	}
	return id, rows.Err()
}
func (s *Store) CreateSession(ctx context.Context, k [32]byte, csrf string, id browserauth.Identity, expires time.Time) error {
	// Recheck membership and enabled flags to close the provisioning race.
	result, err := s.db.ExecContext(ctx, `INSERT INTO gateway_identity.browser_sessions(session_hash,identity_id,account_id,csrf_token,expires_at)
 SELECT $1,i.identity_id,m.account_id,$2,$3
 FROM gateway_identity.oidc_identities i
 JOIN gateway_identity.users u ON u.user_id=i.user_id AND u.enabled
 JOIN gateway_identity.account_memberships m ON m.user_id=i.user_id AND m.enabled AND m.account_id=$5
 WHERE i.identity_id=$4::uuid`, k[:], csrf, expires, id.IdentityID, id.AccountID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return browserauth.ErrNotFound
	}
	return nil
}
func (s *Store) LoadSession(ctx context.Context, k [32]byte) (browserauth.Session, error) {
	var session browserauth.Session
	var read, write bool
	err := s.db.QueryRowContext(ctx, `SELECT u.user_id::text,m.account_id,m.can_read,m.can_write,s.csrf_token
 FROM gateway_identity.browser_sessions s
 JOIN gateway_identity.oidc_identities i ON i.identity_id=s.identity_id
 JOIN gateway_identity.users u ON u.user_id=i.user_id AND u.enabled
 JOIN gateway_identity.account_memberships m ON m.user_id=i.user_id AND m.account_id=s.account_id AND m.enabled
 WHERE s.session_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>now()`, k[:]).Scan(
		&session.Principal.SubjectID, &session.Principal.AccountID, &read, &write, &session.CSRFToken)
	if errors.Is(err, sql.ErrNoRows) {
		return browserauth.Session{}, browserauth.ErrNotFound
	}
	if err != nil {
		return browserauth.Session{}, err
	}
	if read {
		session.Principal.Permissions = append(session.Principal.Permissions, auth.OrdersRead)
	}
	if write {
		session.Principal.Permissions = append(session.Principal.Permissions, auth.OrdersWrite)
	}
	return session, nil
}
func (s *Store) RevokeSession(ctx context.Context, k [32]byte) error {
	result, err := s.db.ExecContext(ctx, `UPDATE gateway_identity.browser_sessions SET revoked_at=now() WHERE session_hash=$1 AND revoked_at IS NULL`, k[:])
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return browserauth.ErrNotFound
	}
	return nil
}
func (s *Store) Prune(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM gateway_identity.login_flows WHERE expires_at<now()`); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM gateway_identity.browser_sessions WHERE expires_at<now() OR revoked_at<now()-interval '1 day'`)
	return err
}

var _ browserauth.Store = (*Store)(nil)
