package v1

import (
	"net/http"
	"time"

	"github.com/go-openapi/strfmt"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver/router"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func (c *Controller) CheckInAllowlistBulk(w http.ResponseWriter, r *http.Request) {
	var req models.BulkCheckAllowlistRequest

	if err := router.BindJSON(r, &req); err != nil {
		router.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}

	if len(req.Targets) == 0 {
		router.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "targets list cannot be empty"})
		return
	}

	resp := models.BulkCheckAllowlistResponse{
		Results: make([]*models.BulkCheckAllowlistResult, 0),
	}

	for _, target := range req.Targets {
		lists, err := c.DBClient.IsAllowlistedBy(r.Context(), target)
		if err != nil {
			c.HandleDBErrors(w, err)
			return
		}

		if len(lists) == 0 {
			continue
		}

		resp.Results = append(resp.Results, &models.BulkCheckAllowlistResult{
			Target: &target,
			Allowlists: lists,
		})
	}

	router.WriteJSON(w, http.StatusOK, resp)
}

func (c *Controller) CheckInAllowlist(w http.ResponseWriter, r *http.Request) {
	value := router.PathValue(r, "ip_or_range")

	if value == "" {
		router.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "value is required"})
		return
	}

	allowlisted, reason, err := c.DBClient.IsAllowlisted(r.Context(), value)
	if err != nil {
		c.HandleDBErrors(w, err)
		return
	}

	if r.Method == http.MethodHead {
		if allowlisted {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}

		return
	}

	resp := models.CheckAllowlistResponse{
		Allowlisted: allowlisted,
		Reason:      reason,
	}

	router.WriteJSON(w, http.StatusOK, resp)
}

func (c *Controller) GetAllowlists(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()

	withContent := params.Get("with_content") == "true"

	allowlists, err := c.DBClient.ListAllowLists(r.Context(), withContent)
	if err != nil {
		c.HandleDBErrors(w, err)
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

	router.WriteJSON(w, http.StatusOK, resp)
}

func (c *Controller) GetAllowlist(w http.ResponseWriter, r *http.Request) {
	allowlist := router.PathValue(r, "allowlist_name")

	params := r.URL.Query()
	withContent := params.Get("with_content") == "true"

	allowlistModel, err := c.DBClient.GetAllowList(r.Context(), allowlist, withContent)
	if err != nil {
		c.HandleDBErrors(w, err)
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

	router.WriteJSON(w, http.StatusOK, resp)
}
