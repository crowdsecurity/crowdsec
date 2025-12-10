package middlewares

import (
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver/router"
)

// LoggingMiddleware creates a middleware that logs HTTP requests using the provided logger
// It logs: client IP, timestamp, method, path, protocol, status code, latency, user agent, and error message
// Matches the format used by Gin's LoggerWithFormatter
// If logger is nil, it falls back to the standard logger
func LoggingMiddleware(logger *log.Entry) router.Middleware {
	if logger == nil {
		logger = log.StandardLogger().WithFields(nil)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			path := r.URL.Path
			if r.URL.RawQuery != "" {
				path += "?" + r.URL.RawQuery
			}

			// Create a response writer wrapper to capture status code
			wrapped := &responseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			// Process the request
			next.ServeHTTP(wrapped, r)

			// Calculate latency
			latency := time.Since(start)

			// Get client IP from context (resolved by ClientIPMiddleware)
			// Falls back to RemoteAddr if not set (shouldn't happen if middleware is properly configured)
			clientIP := router.GetClientIP(r)

			// Format latency as string (matches Gin's format)
			latencyStr := latency.String()

			// Log the request in the same format as Gin's LoggerWithFormatter
			// Use the provided logger which writes to the access log file
			// Format the log message and write it directly to the logger's output writer
			// This bypasses logrus formatting since access logs use a specific plain text format
			logMsg := fmt.Sprintf("%s - [%s] \"%s %s %s %d %s %q %s\"\n",
				clientIP,
				start.Format(time.RFC1123),
				r.Method,
				r.URL.Path,
				r.Proto,
				wrapped.statusCode,
				latencyStr,
				r.UserAgent(),
				"", // Error message (empty for now, could be enhanced)
			)
			// Ignore write errors - we don't want logging failures to affect request handling
			_, _ = logger.Logger.Out.Write([]byte(logMsg))
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
