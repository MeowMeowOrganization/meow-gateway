package identitypg

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/MeowMeowOrganization/meow-gateway/internal/auth"
	"github.com/MeowMeowOrganization/meow-gateway/internal/browserauth"
)

// Requires the migration already applied. No Docker orchestration is hidden in tests.
// GATEWAY_IDENTITY_INTEGRATION_DSN=postgres://... go test ./internal/identitypg -v
func TestRealPostgresSessionRevocationAndMembership(t *testing.T) {
	dsn := os.Getenv("GATEWAY_IDENTITY_INTEGRATION_DSN")
	if dsn == "" {
		t.Skip("set GATEWAY_IDENTITY_INTEGRATION_DSN for real PostgreSQL tests")
	}
	ctx := context.Background()
	store, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	db := store.db
	var user string
	if err = db.QueryRowContext(ctx, `INSERT INTO gateway_identity.users DEFAULT VALUES RETURNING user_id::text`).Scan(&user); err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(context.Background(), `DELETE FROM gateway_identity.users WHERE user_id=$1::uuid`, user)
	var unique [16]byte
	if _, err = rand.Read(unique[:]); err != nil {
		t.Fatal(err)
	}
	sub := "ci-" + hex.EncodeToString(unique[:])
	account := "acct-" + sub
	var identity string
	if err = db.QueryRowContext(ctx, `INSERT INTO gateway_identity.oidc_identities(user_id,issuer,subject) VALUES($1::uuid,$2,$3) RETURNING identity_id::text`, user, "https://test-issuer.example", sub).Scan(&identity); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO gateway_identity.account_memberships(user_id,account_id,can_read,can_write) VALUES($1::uuid,$2,true,false)`, user, account); err != nil {
		t.Fatal(err)
	}
	id, err := store.ResolveIdentity(ctx, "https://test-issuer.example", sub)
	if err != nil || id.IdentityID != identity || id.AccountID != account {
		t.Fatalf("provision lookup %+v: %v", id, err)
	}
	flowKey := sha256.Sum256([]byte(sub + "-flow"))
	flow := browserauth.Flow{Nonce: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG", Verifier: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG", ExpiresAt: time.Now().Add(time.Minute)}
	if err = store.SaveFlow(ctx, flowKey, flow); err != nil {
		t.Fatal(err)
	}
	if _, err = store.TakeFlow(ctx, flowKey); err != nil {
		t.Fatal(err)
	}
	if _, err = store.TakeFlow(ctx, flowKey); !errors.Is(err, browserauth.ErrNotFound) {
		t.Fatalf("flow replay %v", err)
	}
	tokenHash := sha256.Sum256([]byte(sub + "-session"))
	csrf := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	if err = store.CreateSession(ctx, tokenHash, csrf, id, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	sess, err := store.LoadSession(ctx, tokenHash)
	if err != nil || sess.Principal.AccountID != account || !sess.Principal.HasPermission(auth.OrdersRead) || sess.Principal.HasPermission(auth.OrdersWrite) {
		t.Fatalf("loaded session %+v: %v", sess, err)
	}
	// Permission changes are read live, never cached in the cookie or session.
	if _, err = db.ExecContext(ctx, `UPDATE gateway_identity.account_memberships SET can_write=true WHERE user_id=$1::uuid`, user); err != nil {
		t.Fatal(err)
	}
	sess, err = store.LoadSession(ctx, tokenHash)
	if err != nil || !sess.Principal.HasPermission(auth.OrdersWrite) {
		t.Fatal("updated permission not observed")
	}
	if _, err = db.ExecContext(ctx, `UPDATE gateway_identity.users SET enabled=false WHERE user_id=$1::uuid`, user); err != nil {
		t.Fatal(err)
	}
	if _, err = store.LoadSession(ctx, tokenHash); !errors.Is(err, browserauth.ErrNotFound) {
		t.Fatalf("disabled user allowed: %v", err)
	}
	if _, err = db.ExecContext(ctx, `UPDATE gateway_identity.users SET enabled=true WHERE user_id=$1::uuid`, user); err != nil {
		t.Fatal(err)
	}
	if err = store.RevokeSession(ctx, tokenHash); err != nil {
		t.Fatal(err)
	}
	if _, err = store.LoadSession(ctx, tokenHash); !errors.Is(err, browserauth.ErrNotFound) {
		t.Fatalf("revoked session allowed: %v", err)
	}
	if err = store.RevokeSession(ctx, tokenHash); !errors.Is(err, browserauth.ErrNotFound) {
		t.Fatalf("duplicate revoke: %v", err)
	}
	if _, err = store.ResolveIdentity(ctx, "https://test-issuer.example", "not-linked"); !errors.Is(err, browserauth.ErrNotFound) {
		t.Fatalf("unlinked identity allowed: %v", err)
	}
}
