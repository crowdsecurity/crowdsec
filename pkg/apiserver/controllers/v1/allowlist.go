package v1

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csnet"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func (c *Controller) CheckInAllowlistBulk(gctx *gin.Context) {
	var req models.BulkCheckAllowlistRequest

	if err := gctx.ShouldBindJSON(&req); err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	if len(req.Targets) == 0 {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": "targets list cannot be empty"})
		return
	}

	resp := models.BulkCheckAllowlistResponse{
		Results: make([]*models.BulkCheckAllowlistResult, 0),
	}

	for _, target := range req.Targets {
		lists, err := c.DBClient.IsAllowlistedBy(gctx.Request.Context(), target)
		if err != nil {
			c.HandleDBErrors(gctx, err)
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

	gctx.JSON(http.StatusOK, resp)
}

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

func (c *Controller) CreateAllowlist(gctx *gin.Context) {
	var req models.CreateAllowlistRequest

	if err := gctx.ShouldBindJSON(&req); err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	if req.Name == nil || *req.Name == "" {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": "name is required"})
		return
	}

	ctx := gctx.Request.Context()

	// the db layer doesn't tell a name conflict apart from any other error
	if _, err := c.DBClient.GetAllowList(ctx, *req.Name, false); err == nil {
		gctx.JSON(http.StatusConflict, gin.H{"message": fmt.Sprintf("allowlist '%s' already exists", *req.Name)})
		return
	}

	allowlist, err := c.DBClient.CreateAllowList(ctx, *req.Name, req.Description, "", false)
	if err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	machineID, _ := getMachineIDFromContext(gctx)
	log.Infof("allowlist %s created by machine %s", allowlist.Name, machineID)

	resp := models.GetAllowlistResponse{
		Name:        allowlist.Name,
		Description: allowlist.Description,
		CreatedAt:   strfmt.DateTime(allowlist.CreatedAt),
		UpdatedAt:   strfmt.DateTime(allowlist.UpdatedAt),
		Items:       make([]*models.AllowlistItem, 0),
	}

	gctx.JSON(http.StatusCreated, resp)
}

// getLocalAllowlist returns nil after replying to the client if the allowlist cannot be modified
func (c *Controller) getLocalAllowlist(gctx *gin.Context, withContent bool) *ent.AllowList {
	name := gctx.Param("allowlist_name")

	allowlist, err := c.DBClient.GetAllowList(gctx.Request.Context(), name, withContent)
	if err != nil {
		c.HandleDBErrors(gctx, err)
		return nil
	}

	// same as cscli, changes would be overwritten by the next sync
	if allowlist.FromConsole {
		gctx.JSON(http.StatusForbidden, gin.H{"message": fmt.Sprintf("allowlist %s is managed by console", name)})
		return nil
	}

	return allowlist
}

func (c *Controller) DeleteAllowlist(gctx *gin.Context) {
	allowlist := c.getLocalAllowlist(gctx, false)
	if allowlist == nil {
		return
	}

	if err := c.DBClient.DeleteAllowList(gctx.Request.Context(), allowlist.Name, false); err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	machineID, _ := getMachineIDFromContext(gctx)
	log.Infof("allowlist %s deleted by machine %s", allowlist.Name, machineID)

	gctx.Status(http.StatusNoContent)
}

func (c *Controller) AddAllowlistItems(gctx *gin.Context) {
	var req models.AddAllowlistItemsRequest

	if err := gctx.ShouldBindJSON(&req); err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	if len(req.Items) == 0 {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": "items list cannot be empty"})
		return
	}

	// AddToAllowlist skips invalid values without reporting them
	for _, item := range req.Items {
		if item == nil || item.Value == "" {
			gctx.JSON(http.StatusBadRequest, gin.H{"message": "value is required"})
			return
		}

		if _, err := csnet.NewRange(item.Value); err != nil {
			gctx.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			return
		}
	}

	allowlist := c.getLocalAllowlist(gctx, true)
	if allowlist == nil {
		return
	}

	known := make(map[string]struct{})
	for _, item := range allowlist.Edges.AllowlistItems {
		known[item.Value] = struct{}{}
	}

	toAdd := make([]*models.AllowlistItem, 0)

	for _, item := range req.Items {
		if _, ok := known[item.Value]; ok {
			continue
		}

		known[item.Value] = struct{}{}

		toAdd = append(toAdd, &models.AllowlistItem{
			Value:       item.Value,
			Description: item.Description,
			Expiration:  item.Expiration,
		})
	}

	ctx := gctx.Request.Context()
	added := 0

	if len(toAdd) > 0 {
		var err error

		added, err = c.DBClient.AddToAllowlist(ctx, allowlist, toAdd)
		if err != nil {
			c.HandleDBErrors(gctx, err)
			return
		}

		machineID, _ := getMachineIDFromContext(gctx)
		log.Infof("%d values added to allowlist %s by machine %s", added, allowlist.Name, machineID)
	}

	// same as cscli, the allowlist is otherwise only checked for new alerts
	expired, err := c.DBClient.ApplyAllowlistsToExistingDecisions(ctx)
	if err != nil {
		c.HandleDBErrors(gctx, fmt.Errorf("unable to apply allowlists to existing decisions: %w", err))
		return
	}

	resp := models.AddAllowlistItemsResponse{
		Added:            new(int64(added)),
		DecisionsExpired: new(int64(expired)),
	}

	gctx.JSON(http.StatusOK, resp)
}

func (c *Controller) RemoveAllowlistItems(gctx *gin.Context) {
	values := gctx.QueryArray("value")
	if len(values) == 0 {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": "value is required"})
		return
	}

	allowlist := c.getLocalAllowlist(gctx, false)
	if allowlist == nil {
		return
	}

	removed, err := c.DBClient.RemoveFromAllowlist(gctx.Request.Context(), allowlist, values...)
	if err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	machineID, _ := getMachineIDFromContext(gctx)
	log.Infof("%d values removed from allowlist %s by machine %s", removed, allowlist.Name, machineID)

	resp := models.RemoveAllowlistItemsResponse{
		Removed: new(int64(removed)),
	}

	gctx.JSON(http.StatusOK, resp)
}
