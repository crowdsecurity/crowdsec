package middlewares

import (
	"net"
	"net/http"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver/router"
)

// ClientIPMiddleware creates a middleware that extracts and sets the client IP from trusted proxy headers
// It resolves the real client IP once using trusted proxy configuration and stores it in the request context
// Downstream handlers can then use router.GetClientIP() to retrieve the resolved IP
// If useForwardedForHeaders is false, only RemoteAddr is used (forwarded headers are ignored)
func ClientIPMiddleware(trustedProxies []net.IPNet, useForwardedForHeaders bool) router.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Resolve the client IP using trusted proxy configuration
			// Only check forwarded headers if the flag is enabled
			var clientIP string
			if useForwardedForHeaders {
				clientIP = router.ResolveClientIP(r, trustedProxies)
			} else {
				// Only use RemoteAddr, ignore forwarded headers
				if r.RemoteAddr == "@" {
					clientIP = "127.0.0.1"
				} else {
					host, _, err := net.SplitHostPort(r.RemoteAddr)
					if err != nil {
						clientIP = r.RemoteAddr
					} else {
						clientIP = host
					}
				}
			}

			// Store the resolved IP in context for downstream handlers
			r = router.SetClientIP(r, clientIP)

			next.ServeHTTP(w, r)
		})
	}
}
