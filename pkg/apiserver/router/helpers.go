package router

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Context key for client IP
type clientIPKey struct{}

// SetClientIP stores the resolved client IP in the request context
// This should be called by middleware that resolves the IP from trusted proxy headers
func SetClientIP(r *http.Request, ip string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), clientIPKey{}, ip))
}

// GetClientIP retrieves the client IP from the request context
// If not set in context, falls back to extracting from RemoteAddr
// This ensures backwards compatibility if middleware hasn't set it
func GetClientIP(r *http.Request) string {
	if ip, ok := r.Context().Value(clientIPKey{}).(string); ok && ip != "" {
		return ip
	}

	// Fallback to RemoteAddr if not in context
	if r.RemoteAddr == "@" {
		return "127.0.0.1"
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}

// PathValue extracts a path parameter from the request
// This is a convenience wrapper around Request.PathValue() (Go 1.22+)
func PathValue(r *http.Request, key string) string {
	return r.PathValue(key)
}

// Query extracts a query parameter from the request URL
// Returns empty string if not found
func Query(r *http.Request, key string) string {
	return r.URL.Query().Get(key)
}

// QueryAll returns all values for a query parameter
func QueryAll(r *http.Request, key string) []string {
	return r.URL.Query()[key]
}

// BindJSON decodes the request body as JSON into the provided value
// The value must be a pointer to the target struct
// Unknown fields are allowed for backwards compatibility with clients that may send extra metadata
func BindJSON(r *http.Request, v any) error {
	decoder := json.NewDecoder(r.Body)
	// Removed DisallowUnknownFields() to maintain backwards compatibility
	// Gin's ShouldBindJSON allowed unknown fields, and existing bouncers/log processors
	// may ship extra metadata, especially when clients are upgraded at different cadences
	return decoder.Decode(v)
}

// JSON writes a JSON response with the given status code
// If encoding fails, it logs the error but does not return an error
// to match the behavior of common web frameworks where JSON encoding errors are rare
// Use WriteJSON if you need error handling
func JSON(w http.ResponseWriter, code int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Errorf("Failed to encode JSON response: %v", err)
		return err
	}
	return nil
}

// WriteJSON writes a JSON response without returning an error
// This is a convenience function that discards encoding errors (which are extremely rare)
func WriteJSON(w http.ResponseWriter, code int, v any) {
	_ = JSON(w, code, v) //nolint:errcheck // JSON encoding errors are extremely rare and already logged in JSON()
}

// SetContextValue stores a value in the request context with the given key
// Returns a new request with the updated context
func SetContextValue(r *http.Request, key, value any) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), key, value))
}

// GetContextValue retrieves a value from the request context by key
// Returns nil if the key is not found
func GetContextValue(r *http.Request, key any) any {
	return r.Context().Value(key)
}

// ClientIP is a convenience wrapper around GetClientIP for backwards compatibility
// The trustedProxies parameter is ignored since IP resolution is handled by middleware
func ClientIP(r *http.Request, trustedProxies []net.IPNet) string {
	return GetClientIP(r)
}

// ResolveClientIP resolves the client IP from the request, respecting trusted proxy headers
// This should be called by middleware to determine the real client IP
// It checks X-Forwarded-For and X-Real-IP headers based on trusted proxy configuration
func ResolveClientIP(r *http.Request, trustedProxies []net.IPNet) string {
	// Handle Unix socket case
	if r.RemoteAddr == "@" {
		return "127.0.0.1"
	}

	// Extract IP from RemoteAddr (format: "IP:port")
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If RemoteAddr doesn't have a port, use it as-is
		host = r.RemoteAddr
	}

	clientIP := net.ParseIP(host)
	if clientIP == nil {
		return host // Return as-is if parsing fails
	}

	// If we have trusted proxies and X-Forwarded-For headers, check them
	if len(trustedProxies) > 0 {
		forwardedFor := r.Header.Get("X-Forwarded-For")
		if forwardedFor != "" {
			// X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
			// We want the leftmost IP that is not in our trusted proxy list
			ips := strings.Split(forwardedFor, ",")
			for i := range ips {
				ips[i] = strings.TrimSpace(ips[i])
				ip := net.ParseIP(ips[i])
				if ip == nil {
					continue
				}

				// Check if this IP is a trusted proxy
				isTrusted := false
				for _, trustedNet := range trustedProxies {
					if trustedNet.Contains(ip) {
						isTrusted = true
						break
					}
				}

				// If this IP is not trusted, it's our client IP
				if !isTrusted {
					return ips[i]
				}
			}
		}

		// Check X-Real-IP header
		realIP := r.Header.Get("X-Real-IP")
		if realIP != "" {
			ip := net.ParseIP(realIP)
			if ip != nil {
				isTrusted := false
				for _, trustedNet := range trustedProxies {
					if trustedNet.Contains(ip) {
						isTrusted = true
						break
					}
				}
				if !isTrusted {
					return realIP
				}
			}
		}
	}

	// Fall back to RemoteAddr
	return clientIP.String()
}

// AbortWithStatus writes a status code and stops further processing
// This is a helper to mimic Gin's AbortWithStatus behavior
// Note: In standard HTTP handlers, you can't truly "abort" - you just return early
// This function sets the status code and can be used before returning
func AbortWithStatus(w http.ResponseWriter, code int) {
	w.WriteHeader(code)
}

// AbortWithJSON writes a JSON response with status code and stops further processing
func AbortWithJSON(w http.ResponseWriter, code int, v any) {
	WriteJSON(w, code, v)
}

// String writes a plain text response
func String(w http.ResponseWriter, code int, s string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	w.Write([]byte(s))
}

// GetHeader retrieves a header value from the request
func GetHeader(r *http.Request, key string) string {
	return r.Header.Get(key)
}

// SetHeader sets a header on the response
func SetHeader(w http.ResponseWriter, key, value string) {
	w.Header().Set(key, value)
}

// IsUnixSocket checks if the request came from a Unix socket
func IsUnixSocket(r *http.Request) bool {
	return r.RemoteAddr == "@"
}

// LogError logs an error with request context
func LogError(r *http.Request, err error, msg string) {
	logger := log.WithError(err)
	if r != nil {
		logger = logger.WithFields(log.Fields{
			"method": r.Method,
			"path":   r.URL.Path,
		})
	}
	logger.Error(msg)
}
