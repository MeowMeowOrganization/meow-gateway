package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSeparateAuthorizationRejectsIncorrectScope(t *testing.T) {
	policy := RequirePermissions(map[string]Permission{
		"/rpc/Get":    OrdersRead,
		"/rpc/Submit": OrdersWrite,
	})
	h := policy(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	ctx, err := WithPrincipal(httptest.NewRequest(http.MethodPost, "/rpc/Get", nil).Context(),
		Principal{AccountID: "account-11", Permissions: []Permission{OrdersRead}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/rpc/Get", http.StatusNoContent},
		{"/rpc/Submit", http.StatusForbidden},
		{"/rpc/Unknown", http.StatusForbidden},
	} {
		req := httptest.NewRequest(http.MethodPost, tc.path, nil).WithContext(ctx)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Fatalf("%s returned %d (want %d)", tc.path, w.Code, tc.want)
		}
	}
}
