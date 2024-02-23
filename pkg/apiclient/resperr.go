package apiclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type ErrorResponse struct {
	models.ErrorResponse
}

func (e *ErrorResponse) Error() string {
	err := fmt.Sprintf("API error: %s", *e.Message)
	if len(e.Errors) > 0 {
		err += fmt.Sprintf(" (%s)", e.Errors)
	}

	return err
}

// CheckResponse verifies the API response and builds an appropriate Go error if necessary.
func CheckResponse(r *http.Response) error {
	if c := r.StatusCode; 200 <= c && c <= 299 || c == 304 {
		return nil
	}

	ret := &ErrorResponse{}

	data, err := io.ReadAll(r.Body)
	if err != nil || len(data) == 0 {
		ret.Message = ptr.Of(fmt.Sprintf("http code %d, no error message", r.StatusCode))
		return ret
	}

	if err := json.Unmarshal(data, ret); err != nil {
		return fmt.Errorf("http code %d, invalid body: %w", r.StatusCode, err)
	}

	return ret
}
