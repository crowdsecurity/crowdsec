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
// Returns empty string if all IPs are trusted or none are valid
func findFirstUntrustedIP(ipList string, trustedProxies []netip.Prefix) string {
	if ipList == "" {
		return ""
	}

	ips := strings.Split(ipList, ",")
	// Iterate backwards (right to left) to find the first untrusted IP
	// This is the closest untrusted proxy/client to us
	for i := len(ips) - 1; i >= 0; i-- {
		ipStr := strings.TrimSpace(ips[i])
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			continue
		}

		// If this IP is not trusted, it's our client IP (or closest untrusted proxy)
		if !isTrustedProxy(addr, trustedProxies) {
			return ipStr
		}
	}

	return ""
}

// isRemoteAddrTrusted checks if RemoteAddr is from a trusted proxy
func isRemoteAddrTrusted(r *http.Request, trustedProxies []netip.Prefix) bool {
	if r.RemoteAddr == "" || r.RemoteAddr == "@" {
		// If RemoteAddr is empty, assume we trust the proxy (for tests)
		return true
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

// ResolveClientIP resolves the client IP from the request, respecting trusted proxy headers
// This should be called by middleware to determine the real client IP
// It checks X-Forwarded-For and X-Real-IP headers based on trusted proxy configuration
func ResolveClientIP(r *http.Request, trustedProxies []netip.Prefix) string {
	// Handle Unix socket case
	if r.RemoteAddr == "@" {
		return "127.0.0.1"
	}

	// If we have trusted proxies, check forwarded headers first (before RemoteAddr)
	// This handles cases where RemoteAddr might be empty (e.g., in tests)
	if len(trustedProxies) > 0 {
		// Check X-Forwarded-For header
		// X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
		// Format: leftmost is original client, rightmost is most recent proxy
		// We iterate backwards (right to left) to find the first untrusted IP
		forwardedFor := r.Header.Get("X-Forwarded-For")
		if forwardedFor != "" {
			if ip := findFirstUntrustedIP(forwardedFor, trustedProxies); ip != "" {
				return ip
			}
		}

		// Check X-Real-IP header
		// X-Real-IP contains the client IP as reported by the proxy
		// While typically a single IP, it may contain multiple IPs (comma-separated) in some configurations
		// We iterate backwards (right to left) like X-Forwarded-For to find the first untrusted IP
		// (The trusted proxy check is about RemoteAddr, not the IP in X-Real-IP)
		realIPHeader := r.Header.Get("X-Real-IP")
		if realIPHeader != "" {
			// Check if RemoteAddr is from a trusted proxy
			if isRemoteAddrTrusted(r, trustedProxies) {
				if ip := findFirstUntrustedIP(realIPHeader, trustedProxies); ip != "" {
					return ip
				}
				// If all IPs in X-Real-IP are trusted, take the first one (leftmost)
				// This handles the case where X-Real-IP contains only trusted proxy IPs
				realIPs := strings.Split(realIPHeader, ",")
				if len(realIPs) > 0 {
					realIP := strings.TrimSpace(realIPs[0])
					if _, err := netip.ParseAddr(realIP); err == nil {
						return realIP
					}
				}
			}
		}
	}

	// Extract IP from RemoteAddr (format: "IP:port")
	// Only fall back to RemoteAddr if no forwarded headers were found
	if r.RemoteAddr == "" {
		return ""
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If RemoteAddr doesn't have a port, use it as-is
		host = r.RemoteAddr
	}

	clientAddr, err := netip.ParseAddr(host)
	if err != nil {
		return host // Return as-is if parsing fails
	}

	// Fall back to RemoteAddr
	return clientAddr.String()
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
