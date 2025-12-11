package middlewares

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver/router"
)

// gzipReadCloser wraps a gzip.Reader and ensures both the gzip reader
// and the original body are closed when Close() is called
type gzipReadCloser struct {
	*gzip.Reader
	originalBody io.ReadCloser
}

func (g *gzipReadCloser) Close() error {
	// Close the gzip reader first
	err1 := g.Reader.Close()
	// Then close the original body to allow connection reuse
	err2 := g.originalBody.Close()
	// Return the first error if any
	if err1 != nil {
		return err1
	}
	return err2
}

// GzipDecompressMiddleware creates a middleware that automatically decompresses gzip-encoded request bodies
// It does NOT compress responses (to avoid breaking existing bouncers)
func GzipDecompressMiddleware() router.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if the request body is gzip-encoded (case-insensitive)
			contentEncoding := strings.ToLower(r.Header.Get("Content-Encoding"))
			if strings.Contains(contentEncoding, "gzip") {
				// Keep reference to original body for proper cleanup
				originalBody := r.Body

				// Create a gzip reader from the request body
				gzipReader, err := gzip.NewReader(originalBody)
				if err != nil {
					// Close original body on error
					originalBody.Close()
					router.AbortWithJSON(w, http.StatusBadRequest, map[string]string{
						"message": "invalid gzip encoding",
					})
					return
				}

				// Wrap in custom ReadCloser that closes both gzip reader and original body
				wrapped := &gzipReadCloser{
					Reader:       gzipReader,
					originalBody: originalBody,
				}

				// Replace the request body with the decompressed reader
				r.Body = wrapped
				// Remove Content-Encoding header since we've decompressed
				r.Header.Del("Content-Encoding")
			}

			next.ServeHTTP(w, r)
			// Note: The standard library will close r.Body after the handler completes.
			// Our gzipReadCloser.Close() ensures both the gzip reader and original body are closed.
		})
	}
}
