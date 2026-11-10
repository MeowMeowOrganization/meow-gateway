package auth

import (
	"net/http"

	"github.com/MeowMeowOrganization/meow-gateway/internal/edgeerrors"
)

// Permission represents an exchange-edge capability. Account IDs are resolved
// from verified credentials, not supplied by API requests.
type Permission string

const (
	OrdersRead  Permission = "orders:read"
	OrdersWrite Permission = "orders:write"
)

func validPermission(p Permission) bool { return p == OrdersRead || p == OrdersWrite }

// RequirePermissions is authorization, not authentication. The exact RPC
// procedure-to-permission table defaults closed for unknown procedures.
// Put this middleware INSIDE Bearer so it can read a verified principal.
func RequirePermissions(procedures map[string]Permission) func(http.Handler) http.Handler {
	mapping := make(map[string]Permission, len(procedures))
	for procedure, permission := range procedures {
		if procedure == "" || !validPermission(permission) {
			panic("auth.RequirePermissions: invalid policy")
		}
		mapping[procedure] = permission
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := PrincipalFromContext(r.Context())
			permission, listed := mapping[r.URL.Path]
			if !ok || !listed || !principal.HasPermission(permission) {
				edgeerrors.WriteHTTP(w, edgeerrors.New(edgeerrors.PermissionDenied, nil))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
