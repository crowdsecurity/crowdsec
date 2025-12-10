package v1

import (
	"errors"
	"net"
	"net/http"
	"strings"

	middlewares "github.com/crowdsecurity/crowdsec/pkg/apiserver/middlewares/v1"
	"github.com/crowdsecurity/crowdsec/pkg/apiserver/router"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
)

func getBouncerFromContext(r *http.Request) (*ent.Bouncer, error) {
	bouncerInterface := router.GetContextValue(r, middlewares.BouncerContextKey)
	if bouncerInterface == nil {
		return nil, errors.New("bouncer not found")
	}

	bouncerInfo, ok := bouncerInterface.(*ent.Bouncer)
	if !ok {
		return nil, errors.New("bouncer not found")
	}

	return bouncerInfo, nil
}

func isUnixSocket(r *http.Request) bool {
	if localAddr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		return strings.HasPrefix(localAddr.Network(), "unix")
	}

	return false
}

func getMachineIDFromContext(r *http.Request) (string, error) {
	// Use the helper from jwt.go
	return middlewares.GetMachineIDFromRequest(r)
}

// AbortRemoteIf creates a middleware that aborts remote requests if the option is enabled
func (*Controller) AbortRemoteIf(option bool) router.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !option {
				next.ServeHTTP(w, r)
				return
			}

			if isUnixSocket(r) {
				next.ServeHTTP(w, r)
				return
			}

			incomingIP := router.GetClientIP(r) // Gets IP from context (resolved by ClientIPMiddleware)
			if incomingIP != "127.0.0.1" && incomingIP != "::1" {
				router.AbortWithJSON(w, http.StatusForbidden, map[string]string{"message": "access forbidden"})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
