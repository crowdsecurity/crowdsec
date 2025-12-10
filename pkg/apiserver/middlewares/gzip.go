package middlewares

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver/router"
)

// GzipDecompressMiddleware creates a middleware that automatically decompresses gzip-encoded request bodies
// It does NOT compress responses (to avoid breaking existing bouncers)
func GzipDecompressMiddleware() router.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if the request body is gzip-encoded
			contentEncoding := r.Header.Get("Content-Encoding")
			if strings.Contains(contentEncoding, "gzip") {
				// Create a gzip reader from the request body
				gzipReader, err := gzip.NewReader(r.Body)
				if err != nil {
					router.AbortWithJSON(w, http.StatusBadRequest, map[string]string{
						"message": "invalid gzip encoding",
					})
					return
				}
				defer gzipReader.Close()

				// Replace the request body with the decompressed reader
				r.Body = io.NopCloser(gzipReader)
				// Remove Content-Encoding header since we've decompressed
				r.Header.Del("Content-Encoding")
			}

			next.ServeHTTP(w, r)
		})
	}
}
