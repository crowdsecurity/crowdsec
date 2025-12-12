package router

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Context key for client IP
type clientIPKey struct{}

// Context key for route pattern
type routePatternKey struct{}

// SetClientIP stores the resolved client IP in the request context
// This should be called by middleware that resolves the IP from trusted proxy headers
func SetClientIP(r *http.Request, ip string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), clientIPKey{}, ip))
}

// SetRoutePattern stores the route pattern (template) in the request context
// This is used for metrics to avoid high cardinality from concrete paths
func SetRoutePattern(r *http.Request, pattern string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), routePatternKey{}, pattern))
}

// GetRoutePattern retrieves the route pattern from the request context
// Falls back to r.URL.Path if not set (for backwards compatibility)
func GetRoutePattern(r *http.Request) string {
	if pattern, ok := r.Context().Value(routePatternKey{}).(string); ok && pattern != "" {
		return pattern
	}
	// If pattern not set, return empty string so invalid endpoint can be used
	return ""
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
	data, err := json.Marshal(v)
	if err != nil {
		log.Errorf("Failed to encode JSON response: %v", err)
		return err
	}
	_, err = w.Write(data)
	return err
}

// WriteJSON writes a JSON response without returning an error
// This is a convenience function that discards encoding errors (which are extremely rare)
func WriteJSON(w http.ResponseWriter, code int, v any) {
	_ = JSON(w, code, v)
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

// isTrustedProxy checks if an IP address is in the trusted proxy list
func isTrustedProxy(addr netip.Addr, trustedProxies []netip.Prefix) bool {
	for _, prefix := range trustedProxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// findFirstUntrustedIP iterates backwards through a comma-separated list of IPs
// and returns the first (rightmost) IP that is not in the trusted proxy list
func findFirstUntrustedIP(ipList string, trustedProxies []netip.Prefix) string {
	if ipList == "" {
		return ""
	}

	ips := strings.Split(ipList, ",")
	for i := len(ips) - 1; i >= 0; i-- {
		ipStr := strings.TrimSpace(ips[i])
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			continue
		}

		if !isTrustedProxy(addr, trustedProxies) {
			return ipStr
		}
	}

	return ""
}

// isRemoteAddrTrusted checks if RemoteAddr is from a trusted proxy
func isRemoteAddrTrusted(r *http.Request, trustedProxies []netip.Prefix) bool {
	if r.RemoteAddr == "" {
		return true
	}

	// Treat Unix sockets as 127.0.0.1 for trusted proxy checking
	if r.RemoteAddr == "@" {
		addr, err := netip.ParseAddr("127.0.0.1")
		if err != nil {
			return false
		}
		return isTrustedProxy(addr, trustedProxies)
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	remoteAddr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}

	return isTrustedProxy(remoteAddr, trustedProxies)
}

// resolveFromForwardedFor extracts client IP from X-Forwarded-For header
func resolveFromForwardedFor(r *http.Request, trustedProxies []netip.Prefix) string {
	forwardedFor := r.Header.Get("X-Forwarded-For")
	if forwardedFor == "" {
		return ""
	}

	return findFirstUntrustedIP(forwardedFor, trustedProxies)
}

// resolveFromRealIP extracts client IP from X-Real-IP header
func resolveFromRealIP(r *http.Request, trustedProxies []netip.Prefix) string {
	realIPHeader := r.Header.Get("X-Real-IP")
	if realIPHeader == "" {
		return ""
	}

	// Check if RemoteAddr is from a trusted proxy
	if !isRemoteAddrTrusted(r, trustedProxies) {
		return ""
	}

	if ip := findFirstUntrustedIP(realIPHeader, trustedProxies); ip != "" {
		return ip
	}

	realIPs := strings.Split(realIPHeader, ",")
	if len(realIPs) == 0 {
		return ""
	}

	realIP := strings.TrimSpace(realIPs[0])
	if _, err := netip.ParseAddr(realIP); err == nil {
		return realIP
	}

	return ""
}

// ResolveClientIP resolves the client IP from the request, respecting trusted proxy headers
func ResolveClientIP(r *http.Request, trustedProxies []netip.Prefix) string {
	isUnixSocket := r.RemoteAddr == "@"

	if len(trustedProxies) == 0 {
		if isUnixSocket {
			return "127.0.0.1"
		}
		return extractIPFromRemoteAddr(r.RemoteAddr)
	}

	if ip := resolveFromForwardedFor(r, trustedProxies); ip != "" {
		return ip
	}

	if ip := resolveFromRealIP(r, trustedProxies); ip != "" {
		return ip
	}

	if isUnixSocket {
		return "127.0.0.1"
	}

	return extractIPFromRemoteAddr(r.RemoteAddr)
}

// extractIPFromRemoteAddr extracts the IP from RemoteAddr, handling port splitting
func extractIPFromRemoteAddr(remoteAddr string) string {
	if remoteAddr == "" {
		return ""
	}

	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}

	return host
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
	_, _ = w.Write([]byte(s))
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
