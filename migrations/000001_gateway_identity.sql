-- CEX 21.2 identity data is owned by the Gateway, NOT the Order Service.
-- Apply once to a dedicated gateway_identity PostgreSQL database with psql -v ON_ERROR_STOP=1.
BEGIN;
CREATE SCHEMA IF NOT EXISTS gateway_identity;

CREATE TABLE gateway_identity.users (
 user_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 enabled boolean NOT NULL DEFAULT true,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE gateway_identity.oidc_identities (
 identity_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 user_id uuid NOT NULL REFERENCES gateway_identity.users(user_id) ON DELETE CASCADE,
 issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 1024),
 subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(issuer, subject)
);
-- Existing sessions must never silently migrate to another user if an OIDC
-- binding is changed. Delete/re-provision instead (FK cascade revokes sessions).
CREATE FUNCTION gateway_identity.reject_oidc_rebinding() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.user_id IS DISTINCT FROM OLD.user_id OR
    NEW.issuer IS DISTINCT FROM OLD.issuer OR
    NEW.subject IS DISTINCT FROM OLD.subject THEN
    RAISE EXCEPTION 'OIDC subject bindings are immutable; delete and re-provision';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER oidc_identity_immutable BEFORE UPDATE OF user_id,issuer,subject
ON gateway_identity.oidc_identities FOR EACH ROW
EXECUTE FUNCTION gateway_identity.reject_oidc_rebinding();
CREATE INDEX oidc_identities_user_idx ON gateway_identity.oidc_identities(user_id);
CREATE TABLE gateway_identity.account_memberships (
 user_id uuid NOT NULL REFERENCES gateway_identity.users(user_id) ON DELETE CASCADE,
 account_id text NOT NULL CHECK(length(account_id) BETWEEN 1 AND 128 AND account_id ~ '^[!-~]+$'),
 can_read boolean NOT NULL DEFAULT false,
 can_write boolean NOT NULL DEFAULT false,
 enabled boolean NOT NULL DEFAULT true,
 PRIMARY KEY(user_id,account_id),
 CHECK(can_read OR can_write)
);
CREATE TABLE gateway_identity.login_flows (
 state_hash bytea PRIMARY KEY CHECK(octet_length(state_hash)=32),
 nonce text NOT NULL CHECK(length(nonce)=43),
 pkce_verifier text NOT NULL CHECK(length(pkce_verifier)=43),
 expires_at timestamptz NOT NULL
);
CREATE INDEX login_flows_expiry_idx ON gateway_identity.login_flows(expires_at);
CREATE TABLE gateway_identity.browser_sessions (
 session_hash bytea PRIMARY KEY CHECK(octet_length(session_hash)=32),
 identity_id uuid NOT NULL REFERENCES gateway_identity.oidc_identities(identity_id) ON DELETE CASCADE,
 account_id text NOT NULL CHECK(length(account_id) BETWEEN 1 AND 128),
 csrf_token text NOT NULL CHECK(length(csrf_token)=43),
 created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL,
 revoked_at timestamptz,
 CHECK(expires_at > created_at)
);
CREATE INDEX browser_sessions_expiry_idx ON gateway_identity.browser_sessions(expires_at);
CREATE INDEX browser_sessions_identity_idx ON gateway_identity.browser_sessions(identity_id);
COMMIT;
