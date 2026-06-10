package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Maximum body size for LAPI queries
// Applies to the decompressed body if it's gzipped
const (
	UnauthenticatedBodyLimit int64 = 2 * 1024 * 1024  // 2 MiB
	AuthenticatedBodyLimit   int64 = 50 * 1024 * 1024 // 50 MiB
)

func BodyLimit(maxSize int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSize)
		}
		c.Next()
	}
}
