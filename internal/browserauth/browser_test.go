package browserauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/MeowMeowOrganization/meow-gateway/internal/auth"
)

type memoryStore struct {
	mu       sync.Mutex
	flows    map[[32]byte]Flow
	sessions map[[32]byte]Session
	revoked  bool
	identity Identity
}

func newMemoryStore() *memoryStore {
	return &memoryStore{flows: make(map[[32]byte]Flow), sessions: make(map[[32]byte]Session), identity: Identity{IdentityID: "uuid-1", AccountID: "trusted-account"}}
}
func (m *memoryStore) SaveFlow(_ context.Context, k [32]byte, f Flow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flows[k] = f
	return nil
}
func (m *memoryStore) TakeFlow(_ context.Context, k [32]byte) (Flow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.flows[k]
	delete(m.flows, k)
	if !ok {
		return Flow{}, ErrNotFound
	}
	return f, nil
}
func (m *memoryStore) ResolveIdentity(_ context.Context, issuer, sub string) (Identity, error) {
	if issuer != "https://issuer.example" || sub != "sub1" || m.identity.IdentityID == "" {
		return Identity{}, ErrNotFound
	}
	return m.identity, nil
}
func (m *memoryStore) CreateSession(_ context.Context, k [32]byte, csrf string, _ Identity, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[k] = Session{Principal: auth.Principal{AccountID: "trusted-account", SubjectID: "user-1", Permissions: []auth.Permission{auth.OrdersRead, auth.OrdersWrite}}, CSRFToken: csrf}
	return nil
}
func (m *memoryStore) LoadSession(_ context.Context, k [32]byte) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.sessions[k]
	if !ok {
		return Session{}, ErrNotFound
	}
	return v, nil
}
func (m *memoryStore) RevokeSession(_ context.Context, k [32]byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, k)
	m.revoked = true
	return nil
}

type fakeProvider struct {
	code     string
	nonce    string
	verifier string
	state    string
}

func (p *fakeProvider) LoginURL(s, n, ch string) string {
	p.state = s
	p.nonce = n
	return "https://issuer.example/authorize?state=" + url.QueryEscape(s) + "&challenge=" + ch
}
func (p *fakeProvider) Exchange(_ context.Context, code, v, n string) (string, error) {
	p.verifier = v
	if code != "valid-code" || n != p.nonce {
		return "", errors.New("invalid")
	}
	return "sub1", nil
}
func makeBrowser(t *testing.T) (*Handler, *memoryStore, *fakeProvider) {
	t.Helper()
	s := newMemoryStore()
	p := &fakeProvider{}
	h, e := New(Config{PublicOrigin: "https://exchange.example", Issuer: "https://issuer.example", Secure: true}, s, p)
	if e != nil {
		t.Fatal(e)
	}
	return h, s, p
}
func login(t *testing.T, h *Handler, p *fakeProvider) (*http.Cookie, *http.Cookie) {
	t.Helper()
	w := httptest.NewRecorder()
	h.Login(w, httptest.NewRequest("GET", "https://exchange.example/auth/login", nil))
	if w.Code != 302 {
		t.Fatalf("login %d", w.Code)
	}
	if p.state == "" || p.nonce == "" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("no OIDC login flow")
	}
	c := w.Result().Cookies()[0]
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Name != "__Host-meow_login" {
		t.Fatalf("unsafe flow cookie %+v", c)
	}
	req := httptest.NewRequest("GET", "https://exchange.example/auth/callback?state="+p.state+"&code=valid-code", nil)
	req.AddCookie(c)
	cb := httptest.NewRecorder()
	h.Callback(cb, req)
	if cb.Code != 303 {
		t.Fatalf("callback=%d body=%s", cb.Code, cb.Body.String())
	}
	var session *http.Cookie
	for _, cookie := range cb.Result().Cookies() {
		if cookie.Name == "__Host-meow_session" {
			session = cookie
		}
	}
	if session == nil || !session.Secure || !session.HttpOnly || session.Domain != "" {
		t.Fatal("unsafe session cookie")
	}
	return c, session
}
func TestFlowSessionCSRFAndLogout(t *testing.T) {
	h, s, p := makeBrowser(t)
	flow, cookie := login(t, h, p)
	// A replay of an already consumed state never issues a second session.
	replay := httptest.NewRequest("GET", "https://exchange.example/auth/callback?state="+p.state+"&code=valid-code", nil)
	replay.AddCookie(flow)
	w := httptest.NewRecorder()
	h.Callback(w, replay)
	if w.Code != 401 {
		t.Fatalf("replay status %d", w.Code)
	}
	request := httptest.NewRequest("GET", "https://exchange.example/auth/session", nil)
	request.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.Session(w, request)
	if w.Code != 200 {
		t.Fatalf("session status %d", w.Code)
	}
	csrf := ""
	for _, session := range s.sessions {
		csrf = session.CSRFToken
	}
	req := httptest.NewRequest("POST", "https://exchange.example/meow.exchange.api.v1alpha1.TradingService/SubmitLimitOrder", nil)
	req.AddCookie(cookie)
	if _, err := h.VerifyRequest(req); err == nil {
		t.Fatal("missing CSRF permitted")
	}
	req.Header.Set("Origin", "https://attacker.example")
	req.Header.Set("X-CSRF-Token", csrf)
	if _, err := h.VerifyRequest(req); err == nil {
		t.Fatal("foreign origin permitted")
	}
	req.Header.Set("Origin", "https://exchange.example")
	principal, err := h.VerifyRequest(req)
	if err != nil || principal.AccountID != "trusted-account" {
		t.Fatalf("valid browser auth %v %v", principal, err)
	}
	logout := httptest.NewRecorder()
	h.Logout(logout, req)
	if logout.Code != 204 || !s.revoked {
		t.Fatalf("logout %d", logout.Code)
	}
	if _, err := h.VerifyRequest(req); err == nil {
		t.Fatal("revoked session permitted")
	}
}
func TestLoginCSRFAndUnprovisionedIdentity(t *testing.T) {
	h, s, p := makeBrowser(t)
	flow, _ := login(t, h, p)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "https://exchange.example/auth/callback?state="+p.state+"&code=valid-code", nil)
	r.AddCookie(&http.Cookie{Name: flow.Name, Value: "wrong"})
	h.Callback(w, r)
	if w.Code != 401 {
		t.Fatalf("wrong state: %d", w.Code)
	}
	s.identity = Identity{} // provisioning must be explicit; no auto-create
	// Create a NEW flow on the same handler with a now-unprovisioned identity.
	w = httptest.NewRecorder()
	h.Login(w, httptest.NewRequest("GET", "https://exchange.example/auth/login", nil))
	flowCookie := w.Result().Cookies()[0]
	request := httptest.NewRequest("GET", "https://exchange.example/auth/callback?state="+p.state+"&code=valid-code", nil)
	request.AddCookie(flowCookie)
	w = httptest.NewRecorder()
	h.Callback(w, request)
	if w.Code != 403 {
		t.Fatalf("unprovisioned login: %d", w.Code)
	}
	h2, _, p2 := makeBrowser(t)
	w = httptest.NewRecorder()
	h2.Login(w, httptest.NewRequest("GET", "https://exchange.example/auth/login", nil))
	r = httptest.NewRequest("GET", "https://exchange.example/auth/callback?state="+p2.state+"&code=valid-code", nil)
	// missing binding cookie denied
	w = httptest.NewRecorder()
	h2.Callback(w, r)
	if w.Code != 401 {
		t.Fatal("missing flow cookie permitted")
	}
}
func TestInsecureBrowserOnlyOnLoopback(t *testing.T) {
	s := newMemoryStore()
	p := &fakeProvider{}
	_, err := New(Config{PublicOrigin: "http://exchange.example", Issuer: "https://issuer.example", Secure: false}, s, p)
	if err == nil {
		t.Fatal("accepted insecure remote origin")
	}
	h, err := New(Config{PublicOrigin: "http://127.0.0.1:8080", Issuer: "https://issuer.example", Secure: false}, s, p)
	if err != nil || h.sessionCookie != "meow_dev_session" {
		t.Fatalf("loopback %v", err)
	}
}
