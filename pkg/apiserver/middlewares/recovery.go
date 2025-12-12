package middlewares

import (
	"net/http"
	"runtime/debug"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver/router"
)

// RecoveryMiddleware creates a middleware that recovers from panics and logs the error
func RecoveryMiddleware() router.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					// Log the panic with stack trace
					log.WithFields(log.Fields{
						"error":  err,
						"path":   r.URL.Path,
						"method": r.Method,
						"stack":  string(debug.Stack()),
					}).Error("Panic recovered")

					// Write 500 error response
					router.AbortWithJSON(w, http.StatusInternalServerError, map[string]string{
						"message": "Internal server error",
					})
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}
