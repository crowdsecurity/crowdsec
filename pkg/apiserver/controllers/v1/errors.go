package v1

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/crowdsecurity/crowdsec/pkg/database"
)

func (c *Controller) HandleDBErrors(gctx *gin.Context, err error) {
	switch {
	case errors.Is(err, database.ItemNotFound):
		gctx.JSON(http.StatusNotFound, gin.H{"message": err.Error()})
		return
	case errors.Is(err, database.UserExists):
		gctx.JSON(http.StatusForbidden, gin.H{"message": err.Error()})
		return
	case errors.Is(err, database.HashError):
		gctx.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	default:
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}
}

// collapseRepeatedPrefix collapses repeated occurrences of a given prefix in the text
func collapseRepeatedPrefix(text string, prefix string) string {
	count := 0
	for strings.HasPrefix(text, prefix) {
		count++
		text = strings.TrimPrefix(text, prefix)
	}

	if count > 0 {
		return prefix + text
	}

	return text
}

// RepeatedPrefixError wraps an error and removes the repeating prefix from its message
type RepeatedPrefixError struct {
	OriginalError error
	Prefix        string
}

func (e RepeatedPrefixError) Error() string {
	return collapseRepeatedPrefix(e.OriginalError.Error(), e.Prefix)
}

func (e RepeatedPrefixError) Unwrap() error {
	return e.OriginalError
}
