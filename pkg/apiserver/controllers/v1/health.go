package v1

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const Version = "1.0.0"

// HealthController handles health check API requests.
type HealthController struct {
	startedAt time.Time
}

// NewHealthController creates a new HealthController.
func NewHealthController() *HealthController {
	return &HealthController{
		startedAt: time.Now().UTC(),
	}
}

// HealthResponse represents the health check response.
type HealthResponse struct {
	Status        string `json:"status"`
	Version       string `json:"version"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}

// GetHealth handles GET /v1/health
// This endpoint does not require authentication.
func (c *HealthController) GetHealth(gctx *gin.Context) {
	uptime := time.Since(c.startedAt).Seconds()

	response := HealthResponse{
		Status:        "ok",
		Version:       Version,
		UptimeSeconds: int64(uptime),
	}

	gctx.JSON(http.StatusOK, response)
}
