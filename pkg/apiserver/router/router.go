package router

import (
	"net/http"
	"strings"
)

// Router wraps http.ServeMux with additional functionality for route groups and middleware
type Router struct {
	mux        *http.ServeMux
	middleware []Middleware
}

// New creates a new Router instance
func New() *Router {
	return &Router{
		mux:        http.NewServeMux(),
		middleware: []Middleware{},
	}
}

// ServeMux returns the underlying http.ServeMux for use with http.Server
func (r *Router) ServeMux() *http.ServeMux {
	return r.mux
}

// ServeHTTP implements http.Handler so Router can be used directly as a handler
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Wrap the mux with middleware - this ensures all requests (including 404/405) go through middleware
	var handler http.Handler = r.mux
	if len(r.middleware) > 0 {
		handler = ChainMiddleware(r.middleware...)(r.mux)
	}
	handler.ServeHTTP(w, req)
	// Note: http.ServeMux will handle 404/405 with its default responses, but they still go through
	// our middleware chain above, so logging/recovery/gzip all work correctly
}

// Use adds middleware to the router that will be applied to all routes
func (r *Router) Use(middlewares ...Middleware) {
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
func (r *Router) HandleFunc(pattern, method string, handler http.HandlerFunc) {
	fullPattern := pattern
	if method != "" {
		fullPattern = method + " " + pattern
	}
	r.mux.HandleFunc(fullPattern, handler)
}

// Handle registers a handler for the given pattern with optional method restriction
// Note: Router-level middleware is applied in ServeHTTP, not here, to ensure 404/405 also go through middleware
func (r *Router) Handle(pattern, method string, handler http.Handler) {
	fullPattern := pattern
	if method != "" {
		fullPattern = method + " " + pattern
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

	// Create wrapped handler with group middleware
	var wrapped http.Handler = handler
	if len(g.middleware) > 0 {
		wrapped = ChainMiddleware(g.middleware...)(handler)
	}

	// Register with router (router-level middleware is applied in ServeHTTP)
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
	g.router.Handle(fullPattern, method, wrapped)
}
