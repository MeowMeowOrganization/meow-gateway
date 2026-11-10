// Package browserauth implements an OIDC-backed browser session boundary.
// It never accepts account identifiers from HTTP requests or OIDC email claims.
package browserauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/MeowMeowOrganization/meow-gateway/internal/auth"
)

var ErrNotFound = errors.New("identity or session not found")

const (
	flowTTL    = 5 * time.Minute
	sessionTTL = 8 * time.Hour
)

type Flow struct {
	Nonce     string
	Verifier  string
	ExpiresAt time.Time
}

type Identity struct {
	IdentityID string
	AccountID  string
}

type Session struct {
	Principal auth.Principal
	CSRFToken string
}

// Store MUST implement atomic one-time flow consumption and durable revocation.
// Sessions are checked against CURRENT user and account membership on every use.
type Store interface {
	SaveFlow(context.Context, [32]byte, Flow) error
	TakeFlow(context.Context, [32]byte) (Flow, error)
	ResolveIdentity(context.Context, string, string) (Identity, error)
	CreateSession(context.Context, [32]byte, string, Identity, time.Time) error
	LoadSession(context.Context, [32]byte) (Session, error)
	RevokeSession(context.Context, [32]byte) error
}

// Provider is an external confidential OIDC client. Exchange MUST validate
// ID-token signature, issuer, audience, expiration, and expected nonce.
type Provider interface {
	LoginURL(state, nonce, challenge string) string
	Exchange(context.Context, string, string, string) (subject string, err error)
}

type Config struct {
	PublicOrigin string // exact https://host[:port] (or explicitly allowed loopback http)
	Issuer       string
	Secure       bool
}

type Handler struct {
	cfg           Config
	store         Store
	provider      Provider
	now           func() time.Time
	sessionCookie string
	flowCookie    string
}

func New(cfg Config, store Store, provider Provider) (*Handler, error) {
	if store == nil || provider == nil || cfg.Issuer == "" {
		return nil, errors.New("browser authentication requires store, OIDC provider and issuer")
	}
	u, err := url.Parse(cfg.PublicOrigin)
	if err != nil || u == nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" ||
		(cfg.Secure && u.Scheme != "https") || (!cfg.Secure && (u.Scheme != "http" || !loopback(u.Hostname()))) || u.String() != cfg.PublicOrigin {
		return nil, errors.New("browser authentication requires an exact public origin and secure cookies (except explicit loopback development)")
	}
	h := &Handler{cfg: cfg, store: store, provider: provider, now: time.Now, sessionCookie: "__Host-meow_session", flowCookie: "__Host-meow_login"}
	if !cfg.Secure {
		h.sessionCookie = "meow_dev_session"
		h.flowCookie = "meow_dev_login"
	}
	return h, nil
}

func loopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host == "::1"
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func digest(s string) [32]byte { return sha256.Sum256([]byte(s)) }
func challenge(verifier string) string {
	d := digest(verifier)
	return base64.RawURLEncoding.EncodeToString(d[:])
}

func (h *Handler) cookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: h.cfg.Secure, SameSite: http.SameSiteLaxMode, MaxAge: maxAge}
}
func (h *Handler) deleteCookie(w http.ResponseWriter, name string) {
	c := h.cookie(name, "", -1)
	c.Expires = time.Unix(1, 0)
	http.SetCookie(w, c)
}
func securityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}
func failure(w http.ResponseWriter, status int) {
	http.Error(w, http.StatusText(status), status)
}
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Method != http.MethodGet || r.URL.RawQuery != "" {
		failure(w, http.StatusBadRequest)
		return
	}
	state, err := randomToken()
	if err != nil {
		failure(w, 500)
		return
	}
	nonce, err := randomToken()
	if err != nil {
		failure(w, 500)
		return
	}
	verifier, err := randomToken()
	if err != nil {
		failure(w, 500)
		return
	}
	if err := h.store.SaveFlow(r.Context(), digest(state), Flow{Nonce: nonce, Verifier: verifier, ExpiresAt: h.now().Add(flowTTL)}); err != nil {
		failure(w, 500)
		return
	}
	http.SetCookie(w, h.cookie(h.flowCookie, state, int(flowTTL.Seconds())))
	// An external OIDC authorization endpoint is the only redirect target here.
	http.Redirect(w, r, h.provider.LoginURL(state, nonce, challenge(verifier)), http.StatusFound)
}

func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	h.deleteCookie(w, h.flowCookie)
	if r.Method != http.MethodGet || len(r.URL.RawQuery) > 4096 || r.URL.Query().Get("error") != "" {
		failure(w, http.StatusUnauthorized)
		return
	}
	q := r.URL.Query()
	if len(q["state"]) != 1 || len(q["code"]) != 1 || len(q["code"][0]) == 0 || len(q["code"][0]) > 2048 {
		failure(w, http.StatusUnauthorized)
		return
	}
	state := q.Get("state")
	cookie, ok := singleCookie(r, h.flowCookie)
	if !ok || subtle.ConstantTimeCompare([]byte(state), []byte(cookie)) != 1 {
		failure(w, http.StatusUnauthorized)
		return
	}
	flow, err := h.store.TakeFlow(r.Context(), digest(state))
	if err != nil {
		failure(w, http.StatusUnauthorized)
		return
	}
	if !h.now().Before(flow.ExpiresAt) {
		failure(w, http.StatusUnauthorized)
		return
	}
	subject, err := h.provider.Exchange(r.Context(), q.Get("code"), flow.Verifier, flow.Nonce)
	if err != nil || subject == "" {
		failure(w, http.StatusUnauthorized)
		return
	}
	identity, err := h.store.ResolveIdentity(r.Context(), h.cfg.Issuer, subject)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			failure(w, http.StatusForbidden)
		} else {
			failure(w, http.StatusInternalServerError)
		}
		return
	} // no auto-provisioning or email-based linking
	token, err := randomToken()
	if err != nil {
		failure(w, 500)
		return
	}
	csrf, err := randomToken()
	if err != nil {
		failure(w, 500)
		return
	}
	if err := h.store.CreateSession(r.Context(), digest(token), csrf, identity, h.now().Add(sessionTTL)); err != nil {
		failure(w, 500)
		return
	}
	// CSRF is not in the cookie: /auth/session reveals it only to same-origin JS.
	http.SetCookie(w, h.cookie(h.sessionCookie, token, int(sessionTTL.Seconds())))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func singleCookie(r *http.Request, name string) (string, bool) {
	var value string
	found := false
	for _, c := range r.Cookies() {
		if c.Name != name {
			continue
		}
		if found {
			return "", false
		}
		value = c.Value
		found = true
	}
	if !found || len(value) != 43 {
		return "", false
	}
	b, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != value {
		return "", false
	}
	return value, true
}
func (h *Handler) load(r *http.Request) (string, Session, error) {
	token, ok := singleCookie(r, h.sessionCookie)
	if !ok {
		return "", Session{}, auth.ErrInvalidCredentials
	}
	session, err := h.store.LoadSession(r.Context(), digest(token))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return "", Session{}, auth.ErrInvalidCredentials
		}
		return "", Session{}, err
	}
	if _, err := auth.WithPrincipal(r.Context(), session.Principal); err != nil {
		return "", Session{}, err
	}
	return token, session, nil
}

// VerifyRequest is used only when there is NO Authorization header. An
// Authorization header, even invalid, must never fall back to a cookie.
func (h *Handler) VerifyRequest(r *http.Request) (auth.Principal, error) {
	_, session, err := h.load(r)
	if err != nil {
		return auth.Principal{}, err
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if !h.validMutation(r, session.CSRFToken) {
			return auth.Principal{}, auth.ErrCSRF
		}
	}
	return session.Principal, nil
}
func (h *Handler) validMutation(r *http.Request, csrfToken string) bool {
	origins := r.Header.Values("Origin")
	if len(origins) != 1 || origins[0] != h.cfg.PublicOrigin {
		return false
	}
	tokens := r.Header.Values("X-CSRF-Token")
	if len(tokens) != 1 || len(tokens[0]) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(tokens[0])
	if err != nil || len(raw) != 32 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(tokens[0]), []byte(csrfToken)) == 1
}

func (h *Handler) Session(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Method != http.MethodGet {
		failure(w, http.StatusMethodNotAllowed)
		return
	}
	_, session, err := h.load(r)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			failure(w, http.StatusUnauthorized)
		} else {
			failure(w, http.StatusInternalServerError)
		}
		return
	}
	writeSession(w, session.Principal, session.CSRFToken)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Method != http.MethodPost {
		failure(w, http.StatusMethodNotAllowed)
		return
	}
	token, session, err := h.load(r)
	if err != nil {
		failure(w, http.StatusUnauthorized)
		return
	}
	if !h.validMutation(r, session.CSRFToken) {
		failure(w, http.StatusForbidden)
		return
	}
	if err := h.store.RevokeSession(r.Context(), digest(token)); err != nil {
		failure(w, http.StatusInternalServerError)
		return
	}
	h.deleteCookie(w, h.sessionCookie)
	w.WriteHeader(http.StatusNoContent)
}

// JSONSession is the wire shape returned to the same-origin frontend.
type JSONSession struct {
	AccountID   string            `json:"account_id"`
	SubjectID   string            `json:"subject_id"`
	Permissions []auth.Permission `json:"permissions"`
	CSRFToken   string            `json:"csrf_token"`
}

func writeSession(w http.ResponseWriter, p auth.Principal, csrf string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(JSONSession{AccountID: p.AccountID, SubjectID: p.SubjectID, Permissions: p.Permissions, CSRFToken: csrf})
}
