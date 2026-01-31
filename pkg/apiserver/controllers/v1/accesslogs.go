package v1

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/rawlogstore"
)

// AccessLogsController handles access logs API requests.
type AccessLogsController struct {
	Reader *rawlogstore.Reader
}

// NewAccessLogsController creates a new AccessLogsController.
func NewAccessLogsController(reader *rawlogstore.Reader) *AccessLogsController {
	return &AccessLogsController{
		Reader: reader,
	}
}

// GetAccessLogs handles GET /v1/access-logs
// Query parameters:
//   - since_id: return records with id > since_id (default: 0)
//   - limit: max records to return (default: 1000, max: 5000)
//   - type: filter by acquis_type (e.g., "caddy")
//   - since_ts: filter by timestamp >= since_ts (unix seconds)
//   - include_total: include total count in response (default: false)
func (c *AccessLogsController) GetAccessLogs(gctx *gin.Context) {
	ctx := gctx.Request.Context()

	// Check if reader is available
	if c.Reader == nil {
		gctx.JSON(http.StatusServiceUnavailable, gin.H{
			"message": "access logs storage not enabled",
		})
		return
	}

	// Parse query parameters
	sinceID := int64(0)
	if sinceIDStr := gctx.Query("since_id"); sinceIDStr != "" {
		var err error
		sinceID, err = strconv.ParseInt(sinceIDStr, 10, 64)
		if err != nil || sinceID < 0 {
			gctx.JSON(http.StatusBadRequest, gin.H{
				"message": "invalid since_id parameter",
			})
			return
		}
	}

	limit := 1000
	if limitStr := gctx.Query("limit"); limitStr != "" {
		var err error
		limit, err = strconv.Atoi(limitStr)
		if err != nil || limit <= 0 {
			gctx.JSON(http.StatusBadRequest, gin.H{
				"message": "invalid limit parameter",
			})
			return
		}
		if limit > 5000 {
			limit = 5000
		}
	}

	opts := &rawlogstore.QueryOptions{
		Type: gctx.Query("type"),
	}

	if sinceTsStr := gctx.Query("since_ts"); sinceTsStr != "" {
		sinceTs, err := strconv.ParseInt(sinceTsStr, 10, 64)
		if err != nil || sinceTs < 0 {
			gctx.JSON(http.StatusBadRequest, gin.H{
				"message": "invalid since_ts parameter",
			})
			return
		}
		opts.SinceTs = &sinceTs
	}

	if gctx.Query("include_total") == "true" || gctx.Query("include_total") == "1" {
		opts.IncludeTotal = true
	}

	// Query access logs
	result, err := c.Reader.Query(ctx, sinceID, limit, opts)
	if err != nil {
		log.WithError(err).Error("failed to query access logs")
		gctx.JSON(http.StatusInternalServerError, gin.H{
			"message": "failed to query access logs",
		})
		return
	}

	// Build response
	response := gin.H{
		"items":         result.Items,
		"next_since_id": result.NextSinceID,
		"has_more":      result.HasMore,
	}

	if result.Total != nil {
		response["total_in_db"] = *result.Total
	}

	gctx.JSON(http.StatusOK, response)
}
