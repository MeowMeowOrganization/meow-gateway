package middleware

import (
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/MeowMeowOrganization/meow-gateway/internal/auth"
	"github.com/MeowMeowOrganization/meow-gateway/internal/edgeerrors"
	"github.com/MeowMeowOrganization/meow-gateway/internal/ratelimit"
)

func limited(w http.ResponseWriter, delay time.Duration) {
	seconds := int64((delay + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	edgeerrors.WriteHTTP(w, edgeerrors.New(edgeerrors.ResourceExhausted, nil))
}

// LimitByPeerIP uses only the trusted TCP peer; never a spoofable forwarding
// header. A reverse proxy must impose its own true-client-IP policy.
// Liveness and readiness probes stay outside this limit.
func LimitByPeerIP(limiter *ratelimit.Limiter) Middleware {
	if limiter == nil {
		panic("middleware.LimitByPeerIP: nil limiter")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
				next.ServeHTTP(w, r)
				return
			}
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			ip := net.ParseIP(host)
			if err != nil || ip == nil {
				edgeerrors.WriteHTTP(w, edgeerrors.New(edgeerrors.PermissionDenied, nil))
				return
			}
			if ok, delay := limiter.Allow(ip.String()); !ok {
				limited(w, delay)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// LimitByAccount is installed inside authentication and authorization. The
// account quota never uses a client-supplied identity or forwarding header.
func LimitByAccount(read, write *ratelimit.Limiter, procedures map[string]auth.Permission) Middleware {
	if read == nil || write == nil {
		panic("middleware.LimitByAccount: nil limiter")
	}
	mapping := make(map[string]auth.Permission, len(procedures))
	for k, v := range procedures {
		mapping[k] = v
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := auth.PrincipalFromContext(r.Context())
			if !ok || principal.AccountID == "" {
				edgeerrors.WriteHTTP(w, edgeerrors.New(edgeerrors.Unauthenticated, nil))
				return
			}
			var limiter *ratelimit.Limiter
			switch mapping[r.URL.Path] {
			case auth.OrdersRead:
				limiter = read
			case auth.OrdersWrite:
				limiter = write
			default:
				edgeerrors.WriteHTTP(w, edgeerrors.New(edgeerrors.PermissionDenied, nil))
				return
			}
			if allowed, delay := limiter.Allow(principal.AccountID); !allowed {
				limited(w, delay)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
