package router

import (
	"net/http"
	"strings"
)

// Middleware is a function that wraps an http.Handler
// Standard Go middleware pattern
type Middleware func(http.Handler) http.Handler

// ChainMiddleware chains multiple middlewares together
// The first middleware in the slice is the outermost (executes first)
// The last middleware in the slice is the innermost (executes last)
func ChainMiddleware(middlewares ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}
		return next
	}
}

// AdaptHandlerFunc converts an http.HandlerFunc to an http.Handler
// This is useful when mixing Handler and HandlerFunc types
func AdaptHandlerFunc(fn http.HandlerFunc) http.Handler {
	return fn
}

// MethodNotAllowedHandler returns a handler that responds with 405 Method Not Allowed
func MethodNotAllowedHandler(allowedMethods ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", strings.Join(allowedMethods, ", "))
		AbortWithStatus(w, http.StatusMethodNotAllowed)
	})
}

// NotFoundHandler returns a handler that responds with 404 Not Found
func NotFoundHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = JSON(w, http.StatusNotFound, map[string]string{"message": "Page or Method not found"})
	})
}
