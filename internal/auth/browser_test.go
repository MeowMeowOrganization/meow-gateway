package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeCookieVerifier struct {
	principal Principal
	err       error
	calls     int
}

func (c *fakeCookieVerifier) VerifyRequest(_ *http.Request) (Principal, error) {
	c.calls++
	return c.principal, c.err
}
func TestBearerOrSessionNeverFallsBackFromInvalidBearer(t *testing.T) {
	bearer := &fakeVerifier{err: ErrInvalidCredentials}
	browser := &fakeCookieVerifier{principal: Principal{AccountID: "browser-account"}}
	middleware := BearerOrSession(bearer, browser)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	r := httptest.NewRequest("POST", "/rpc", nil)
	r.Header.Set("Authorization", "Bearer invalid")
	w := httptest.NewRecorder()
	middleware.ServeHTTP(w, r)
	if w.Code != 401 || browser.calls != 0 {
		t.Fatalf("bearer fallback code %d calls %d", w.Code, browser.calls)
	}
	r = httptest.NewRequest("POST", "/rpc", nil)
	w = httptest.NewRecorder()
	middleware.ServeHTTP(w, r)
	if w.Code != 204 || browser.calls != 1 {
		t.Fatalf("browser auth code %d calls %d", w.Code, browser.calls)
	}
	browser.err = ErrCSRF
	w = httptest.NewRecorder()
	middleware.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("CSRF status %d", w.Code)
	}
}
