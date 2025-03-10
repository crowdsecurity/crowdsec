package v1

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-openapi/strfmt"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func (c *Controller) CheckInAllowlist(gctx *gin.Context) {
	value := gctx.Param("ip_or_range")

	if value == "" {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": "value is required"})
		return
	}

	allowlisted, reason, err := c.DBClient.IsAllowlisted(gctx.Request.Context(), value)
	if err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	if gctx.Request.Method == http.MethodHead {
		if allowlisted {
			gctx.Status(http.StatusOK)
		} else {
			gctx.Status(http.StatusNoContent)
		}

		return
	}

	resp := models.CheckAllowlistResponse{
		Allowlisted: allowlisted,
		Reason:      reason,
	}

	gctx.JSON(http.StatusOK, resp)
}

func (c *Controller) GetAllowlists(gctx *gin.Context) {
	params := gctx.Request.URL.Query()

	withContent := params.Get("with_content") == "true"

	allowlists, err := c.DBClient.ListAllowLists(gctx.Request.Context(), withContent)
	if err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	resp := models.GetAllowlistsResponse{}

	for _, allowlist := range allowlists {
		items := make([]*models.AllowlistItem, 0)

		if withContent {
			for _, item := range allowlist.Edges.AllowlistItems {
				if !item.ExpiresAt.IsZero() && item.ExpiresAt.Before(time.Now()) {
					continue
				}

				items = append(items, &models.AllowlistItem{
					CreatedAt:   strfmt.DateTime(item.CreatedAt),
					Description: item.Comment,
					Expiration:  strfmt.DateTime(item.ExpiresAt),
					Value:       item.Value,
				})
			}
		}

		resp = append(resp, &models.GetAllowlistResponse{
			AllowlistID:    allowlist.AllowlistID,
			Name:           allowlist.Name,
			Description:    allowlist.Description,
			CreatedAt:      strfmt.DateTime(allowlist.CreatedAt),
			UpdatedAt:      strfmt.DateTime(allowlist.UpdatedAt),
			ConsoleManaged: allowlist.FromConsole,
			Items:          items,
		})
	}

	gctx.JSON(http.StatusOK, resp)
}

func (c *Controller) GetAllowlist(gctx *gin.Context) {
	allowlist := gctx.Param("allowlist_name")

	params := gctx.Request.URL.Query()
	withContent := params.Get("with_content") == "true"

	allowlistModel, err := c.DBClient.GetAllowList(gctx.Request.Context(), allowlist, withContent)
	if err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	items := make([]*models.AllowlistItem, 0)

	if withContent {
		for _, item := range allowlistModel.Edges.AllowlistItems {
			if !item.ExpiresAt.IsZero() && item.ExpiresAt.Before(time.Now()) {
				continue
			}

			items = append(items, &models.AllowlistItem{
				CreatedAt:   strfmt.DateTime(item.CreatedAt),
				Description: item.Comment,
				Expiration:  strfmt.DateTime(item.ExpiresAt),
				Value:       item.Value,
			})
		}
	}

	resp := models.GetAllowlistResponse{
		AllowlistID:    allowlistModel.AllowlistID,
		Name:           allowlistModel.Name,
		Description:    allowlistModel.Description,
		CreatedAt:      strfmt.DateTime(allowlistModel.CreatedAt),
		UpdatedAt:      strfmt.DateTime(allowlistModel.UpdatedAt),
		ConsoleManaged: allowlistModel.FromConsole,
		Items:          items,
	}

	gctx.JSON(http.StatusOK, resp)
}
