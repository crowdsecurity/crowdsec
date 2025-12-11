package router

import (
	"net/http"
	"strings"
)

// Router wraps http.ServeMux with additional functionality for route groups and middleware
type Router struct {
	mux            *http.ServeMux
	middleware     []Middleware
	wrappedHandler http.Handler      // Cached handler with middleware chain (built once via Build())
	patternMap     map[string]string // Maps fullPattern (method + path) to route template
	built          bool              // Whether Build() has been called
}

const (
	// UnknownRoutePattern is the sentinel pattern used for unmatched routes (404/405)
	// This ensures metrics cardinality stays bounded for unknown routes
	UnknownRoutePattern = "invalid-endpoint"
)

// New creates a new Router instance
func New() *Router {
	return &Router{
		mux:        http.NewServeMux(),
		middleware: []Middleware{},
		patternMap: make(map[string]string),
		built:      false,
	}
}

// ServeMux returns the underlying http.ServeMux for use with http.Server
func (r *Router) ServeMux() *http.ServeMux {
	return r.mux
}

// ServeHTTP implements http.Handler so Router can be used directly as a handler
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Use cached wrapped handler (built via Build())
	r.wrappedHandler.ServeHTTP(w, req)
	// Note: http.ServeMux will handle 404/405 with its default responses, but they still go through
	// our middleware chain above, so logging/recovery/gzip all work correctly
}

// matchPattern finds the route template that matches the given method and path
// Supports path variables (e.g., /v1/alerts/{alert_id} matches /v1/alerts/123)
// Returns UnknownRoutePattern if no match is found
// Safe to call without locks since patternMap is read-only after Build()
func (r *Router) matchPattern(method, path string) string {
	// Try exact match first: "GET /v1/alerts/{alert_id}"
	methodPath := method + " " + path
	if pattern, ok := r.patternMap[methodPath]; ok {
		return pattern
	}

	// Try path-only match: "/v1/alerts/{alert_id}"
	if pattern, ok := r.patternMap[path]; ok {
		return pattern
	}

	// Try to match against patterns with variables
	// Compare segment by segment using matchesPattern helper
	for storedPattern, template := range r.patternMap {
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

		// Check if pattern has variables and matches path
		if strings.Contains(patternPath, "{") && matchesPattern(path, patternPath) {
			return template
		}
	}

	// Return sentinel pattern for unknown routes to bound metrics cardinality
	return UnknownRoutePattern
}

// matchesPattern checks if a concrete path matches a pattern with variables
// e.g., /v1/alerts/123 matches /v1/alerts/{alert_id}
func matchesPattern(path, pattern string) bool {
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

// routePatternMiddleware sets the route pattern in context before other middleware runs
// This must be the first middleware so metrics see the template pattern
// Unknown routes get UnknownRoutePattern to bound metrics cardinality
func (r *Router) routePatternMiddleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			pattern := r.matchPattern(req.Method, req.URL.Path)
			req = SetRoutePattern(req, pattern)
			next.ServeHTTP(w, req)
		})
	}
}

// Build finalizes the router by building the wrapped handler with all middleware
// This should be called once after all routes and middleware are registered
// After Build(), the router is read-only and safe for concurrent use
func (r *Router) Build() {
	if r.built {
		return // Already built, no-op
	}

	middlewares := make([]Middleware, 0, len(r.middleware)+1)
	middlewares = append(middlewares, r.routePatternMiddleware())
	middlewares = append(middlewares, r.middleware...)
	r.wrappedHandler = ChainMiddleware(middlewares...)(r.mux)
	r.built = true
}

// Use adds middleware to the router that will be applied to all routes
// Must be called before Build()
func (r *Router) Use(middlewares ...Middleware) {
	if r.built {
		panic("router: cannot add middleware after Build()")
	}
	r.middleware = append(r.middleware, middlewares...)
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
// The pattern is stored for routePatternMiddleware to use for metrics
// Must be called before Build()
func (r *Router) HandleFunc(pattern, method string, handler http.HandlerFunc) {
	if r.built {
		panic("router: cannot register routes after Build()")
	}
	fullPattern := pattern
	if method != "" {
		fullPattern = method + " " + pattern
	}
	// Store pattern mapping for routePatternMiddleware
	r.patternMap[fullPattern] = pattern
	// Only store bare path entry for method-less handlers to avoid template conflicts
	if method == "" {
		r.patternMap[pattern] = pattern
	}
	r.mux.HandleFunc(fullPattern, handler)
}

// Handle registers a handler for the given pattern with optional method restriction
// Note: Router-level middleware is applied in ServeHTTP, not here, to ensure 404/405 also go through middleware
// The pattern is stored for routePatternMiddleware to use for metrics
// Must be called before Build()
func (r *Router) Handle(pattern, method string, handler http.Handler) {
	if r.built {
		panic("router: cannot register routes after Build()")
	}
	fullPattern := pattern
	if method != "" {
		fullPattern = method + " " + pattern
	}
	// Store pattern mapping for routePatternMiddleware
	r.patternMap[fullPattern] = pattern
	// Only store bare path entry for method-less handlers to avoid template conflicts
	if method == "" {
		r.patternMap[pattern] = pattern
	}
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

	// Apply group middleware
	var wrapped http.Handler = handler
	if len(g.middleware) > 0 {
		wrapped = ChainMiddleware(g.middleware...)(handler)
	}

	// Register with router (router-level middleware is applied in ServeHTTP)
	// Router.HandleFunc will store the pattern for routePatternMiddleware
	g.router.HandleFunc(fullPattern, method, func(w http.ResponseWriter, r *http.Request) {
		wrapped.ServeHTTP(w, r)
	})
}

// Handle registers a handler for the given pattern in the group
func (g *Group) Handle(pattern, method string, handler http.Handler) {
	fullPattern := g.prefix + pattern

	// Apply group middleware
	wrapped := handler
	if len(g.middleware) > 0 {
		wrapped = ChainMiddleware(g.middleware...)(handler)
	}

	// Register with router (router-level middleware is applied in ServeHTTP)
	// Router.Handle will store the pattern for routePatternMiddleware
	g.router.Handle(fullPattern, method, wrapped)
}
