package router

import (
	"net/http"
	"strings"
)

// Router wraps http.ServeMux with additional functionality for route groups and middleware
type Router struct {
	mux            *http.ServeMux
	middleware     []Middleware
	wrappedHandler http.Handler      // Cached handler with middleware chain
	patternMap     map[string]string // Maps fullPattern (method + path) to route pattern (path only)
}

// New creates a new Router instance
func New() *Router {
	r := &Router{
		mux:        http.NewServeMux(),
		middleware: []Middleware{},
		patternMap: make(map[string]string),
	}
	// Initialize wrapped handler (no middleware yet, so just the mux)
	r.wrappedHandler = r.mux
	return r
}

// ServeMux returns the underlying http.ServeMux for use with http.Server
func (r *Router) ServeMux() *http.ServeMux {
	return r.mux
}

// ServeHTTP implements http.Handler so Router can be used directly as a handler
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Use cached wrapped handler (built when middleware is added)
	r.wrappedHandler.ServeHTTP(w, req)
	// Note: http.ServeMux will handle 404/405 with its default responses, but they still go through
	// our middleware chain above, so logging/recovery/gzip all work correctly
}

// findPatternWithVariables matches a request path against patterns with variables
func (r *Router) findPatternWithVariables(path, method string) string {
	bestMatch := ""
	bestMatchPattern := ""

	for storedPattern, routePattern := range r.patternMap {
		// Extract method and path from stored pattern
		storedMethod := ""
		patternPath := storedPattern
		if idx := strings.Index(storedPattern, " "); idx > 0 {
			storedMethod = storedPattern[:idx]
			patternPath = storedPattern[idx+1:]
		}

		// Skip if method doesn't match (unless stored pattern has no method)
		if storedMethod != "" && storedMethod != method {
			continue
		}

		// Check if pattern has variables
		if strings.Contains(patternPath, "{") && matchesPattern(path, patternPath) {
			// Use the longest matching pattern (most specific)
			if len(patternPath) > len(bestMatch) {
				bestMatch = patternPath
				bestMatchPattern = routePattern
			}
		}
	}

	return bestMatchPattern
}

// patternSettingMiddleware sets the route pattern in context before other middleware runs
// This must be the first middleware so metrics and logging see the template
func (r *Router) patternSettingMiddleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// Try to find matching pattern
			// First try method + path exact match
			methodPath := req.Method + " " + req.URL.Path
			if pattern, ok := r.patternMap[methodPath]; ok {
				req = SetRoutePattern(req, pattern)
				next.ServeHTTP(w, req)
				return
			}

			// Try path-only exact match (for routes without method restriction)
			if pattern, ok := r.patternMap[req.URL.Path]; ok {
				req = SetRoutePattern(req, pattern)
				next.ServeHTTP(w, req)
				return
			}

			// Try to match against patterns with variables (e.g., /v1/alerts/{id} matches /v1/alerts/123)
			if bestMatchPattern := r.findPatternWithVariables(req.URL.Path, req.Method); bestMatchPattern != "" {
				req = SetRoutePattern(req, bestMatchPattern)
			}

			next.ServeHTTP(w, req)
		})
	}
}

// matchesPattern checks if a concrete path matches a pattern with variables
// e.g., /v1/alerts/123 matches /v1/alerts/{alert_id}
func matchesPattern(path, pattern string) bool {
	// Split both path and pattern by /
	pathParts := strings.Split(strings.Trim(path, "/"), "/")
	patternParts := strings.Split(strings.Trim(pattern, "/"), "/")

	if len(pathParts) != len(patternParts) {
		return false
	}

	for i := range pathParts {
		// If pattern part is a variable {something}, it matches any path part
		if strings.HasPrefix(patternParts[i], "{") && strings.HasSuffix(patternParts[i], "}") {
			continue
		}
		// Otherwise, parts must match exactly
		if pathParts[i] != patternParts[i] {
			return false
		}
	}

	return true
}

// Use adds middleware to the router that will be applied to all routes
func (r *Router) Use(middlewares ...Middleware) {
	r.middleware = append(r.middleware, middlewares...)
	// Pattern setting middleware must run first, before other middleware
	// so metrics and logging see the template instead of concrete paths
	allMiddleware := []Middleware{r.patternSettingMiddleware()}
	allMiddleware = append(allMiddleware, r.middleware...)
	r.wrappedHandler = ChainMiddleware(allMiddleware...)(r.mux)
}

// Group creates a route group with a path prefix
// All routes registered in the group will have the prefix prepended
func (r *Router) Group(prefix string) *Group {
	// Ensure prefix starts with / and doesn't end with /
	prefix = "/" + strings.Trim(prefix, "/")
	if prefix == "/" {
		prefix = ""
	}

	return &Group{
		router: r,
		prefix: prefix,
	}
}

// HandleFunc registers a handler for the given pattern with optional method restriction
// Pattern can use Go 1.22+ path variables like /users/{id}
// If method is empty, it matches all methods
// Note: Router-level middleware is applied in ServeHTTP, not here, to ensure 404/405 also go through middleware
func (r *Router) HandleFunc(pattern, method string, handler http.HandlerFunc) {
	fullPattern := pattern
	if method != "" {
		fullPattern = method + " " + pattern
	}
	// Store pattern mapping for early pattern setting (before middleware)
	r.patternMap[fullPattern] = pattern
	// Also store without method for fallback matching
	r.patternMap[pattern] = pattern
	r.mux.HandleFunc(fullPattern, handler)
}

// Handle registers a handler for the given pattern with optional method restriction
// Note: Router-level middleware is applied in ServeHTTP, not here, to ensure 404/405 also go through middleware
func (r *Router) Handle(pattern, method string, handler http.Handler) {
	fullPattern := pattern
	if method != "" {
		fullPattern = method + " " + pattern
	}
	// Store pattern mapping for early pattern setting (before middleware)
	r.patternMap[fullPattern] = pattern
	// Also store without method for fallback matching
	r.patternMap[pattern] = pattern
	r.mux.Handle(fullPattern, handler)
}

// Group represents a route group with a common prefix
type Group struct {
	router     *Router
	prefix     string
	middleware []Middleware
}

// Group creates a sub-group with an additional path prefix
func (g *Group) Group(prefix string) *Group {
	// Combine prefixes
	fullPrefix := g.prefix
	if prefix != "" {
		if fullPrefix != "" {
			fullPrefix = fullPrefix + "/" + strings.Trim(prefix, "/")
		} else {
			fullPrefix = "/" + strings.Trim(prefix, "/")
		}
	}
	// Copy parent middleware to child group
	parentMiddleware := make([]Middleware, len(g.middleware))
	copy(parentMiddleware, g.middleware)

	return &Group{
		router:     g.router,
		prefix:     fullPrefix,
		middleware: parentMiddleware,
	}
}

// Use adds middleware to the group that will be applied to all routes in the group
func (g *Group) Use(middlewares ...Middleware) {
	g.middleware = append(g.middleware, middlewares...)
}

// HandleFunc registers a handler for the given pattern in the group
// The group prefix is automatically prepended to the pattern
func (g *Group) HandleFunc(pattern, method string, handler http.HandlerFunc) {
	fullPattern := g.prefix + pattern

	// Create wrapped handler with group middleware
	var wrapped http.Handler = handler
	if len(g.middleware) > 0 {
		wrapped = ChainMiddleware(g.middleware...)(handler)
	}

	// Register with router (router-level middleware is applied in ServeHTTP)
	// Router.HandleFunc will set the route pattern in context
	g.router.HandleFunc(fullPattern, method, func(w http.ResponseWriter, r *http.Request) {
		wrapped.ServeHTTP(w, r)
	})
}

// Handle registers a handler for the given pattern in the group
func (g *Group) Handle(pattern, method string, handler http.Handler) {
	fullPattern := g.prefix + pattern

	// Create wrapped handler with group middleware
	wrapped := handler
	if len(g.middleware) > 0 {
		wrapped = ChainMiddleware(g.middleware...)(handler)
	}

	// Register with router (router-level middleware is applied in ServeHTTP)
	// Router.Handle will set the route pattern in context
	g.router.Handle(fullPattern, method, wrapped)
}
