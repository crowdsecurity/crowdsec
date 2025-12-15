package v1

import (
	"errors"
	"net/http"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver/router"
	"github.com/crowdsecurity/crowdsec/pkg/database"
)

func (*Controller) HandleDBErrors(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, database.ItemNotFound):
		router.WriteJSON(w, http.StatusNotFound, map[string]string{"message": err.Error()})
		return
	case errors.Is(err, database.UserExists):
		router.WriteJSON(w, http.StatusForbidden, map[string]string{"message": err.Error()})
		return
	case errors.Is(err, database.HashError):
		router.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	default:
		router.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
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
