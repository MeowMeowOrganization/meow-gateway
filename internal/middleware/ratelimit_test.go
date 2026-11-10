package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MeowMeowOrganization/meow-gateway/internal/auth"
	"github.com/MeowMeowOrganization/meow-gateway/internal/ratelimit"
)

func TestIPLimiterRejectsSpoofedForwardingHeaders(t *testing.T) {
	limiter := ratelimit.New(1, time.Minute, 10)
	h := LimitByPeerIP(limiter)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/market", nil)
		req.RemoteAddr = "198.51.100.7:12345"
		req.Header.Set("X-Forwarded-For", "203.0.113."+string(rune('1'+i)))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		want := http.StatusNoContent
		if i == 1 {
			want = http.StatusTooManyRequests
			if w.Header().Get("Retry-After") == "" {
				t.Fatal("missing Retry-After")
			}
		}
		if w.Code != want {
			t.Fatalf("round %d: %d != %d", i, w.Code, want)
		}
	}
	probe := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	probe.RemoteAddr = "invalid"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, probe)
	if w.Code != http.StatusNoContent {
		t.Fatalf("health probe throttled: %d", w.Code)
	}
}

func TestPerAccountLimiterOnlyUsesVerifiedContext(t *testing.T) {
	policy := map[string]auth.Permission{"/rpc/Submit": auth.OrdersWrite}
	h := LimitByAccount(ratelimit.New(1, time.Minute, 10), ratelimit.New(1, time.Minute, 10), policy)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	ctx, err := auth.WithPrincipal(httptest.NewRequest(http.MethodPost, "/rpc/Submit", nil).Context(), auth.Principal{AccountID: "trusted"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/rpc/Submit", nil).WithContext(ctx)
		req.Header.Set("X-Account-ID", "attacker-"+string(rune('1'+i)))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		want := http.StatusNoContent
		if i == 1 {
			want = http.StatusTooManyRequests
		}
		if w.Code != want {
			t.Fatalf("round %d: %d != %d", i, w.Code, want)
		}
	}
}
