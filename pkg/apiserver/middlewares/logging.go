package middlewares

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
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
			// Only write if the logger level allows info-level messages or more verbose (debug/trace)
			// IsLevelEnabled returns true if logger level >= InfoLevel (i.e., Info, Debug, or Trace)
			if logger.Logger.IsLevelEnabled(log.InfoLevel) {
				// Use concrete path (r.URL.Path) for access logs to show actual requests
				// This is useful for debugging, e.g., seeing which IPs bouncers check in live mode
				// Prometheus metrics use route templates to keep cardinality bounded
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
			}
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture status code
// It also forwards optional interfaces (Flusher, Hijacker, Pusher, ReaderFrom)
// to ensure streaming and connection upgrades work correctly
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Flush implements http.Flusher if the underlying ResponseWriter supports it
func (rw *responseWriter) Flush() {
	if flusher, ok := rw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Hijack implements http.Hijacker if the underlying ResponseWriter supports it
func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, errors.New("underlying ResponseWriter does not implement http.Hijacker")
}

// Push implements http.Pusher if the underlying ResponseWriter supports it
func (rw *responseWriter) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := rw.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return http.ErrNotSupported
}

// ReadFrom implements io.ReaderFrom if the underlying ResponseWriter supports it
func (rw *responseWriter) ReadFrom(src io.Reader) (int64, error) {
	if readerFrom, ok := rw.ResponseWriter.(io.ReaderFrom); ok {
		return readerFrom.ReadFrom(src)
	}
	// Fallback to standard implementation if not supported
	return io.Copy(rw.ResponseWriter, src)
}
