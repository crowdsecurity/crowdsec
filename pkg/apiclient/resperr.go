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
	message := ptr.OrEmpty(e.Message)
	errors := ""

	if e.Errors != "" {
		errors = fmt.Sprintf(" (%s)", e.Errors)
	}

	if message == "" && errors == "" {
		errors = "(no errors)"
	}

	return fmt.Sprintf("API error: %s%s", message, errors)
}

// CheckResponse verifies the API response and builds an appropriate Go error if necessary.
func CheckResponse(r *http.Response) error {
	if c := r.StatusCode; 200 <= c && c <= 299 || c == 304 {
		return nil
	}

	ret := &ErrorResponse{}

	data, err := io.ReadAll(r.Body)
	if err != nil || len(data) == 0 {
		ret.Message = ptr.Of(fmt.Sprintf("http code %d, no response body", r.StatusCode))
		return ret
	}

	switch r.StatusCode {
	case http.StatusUnprocessableEntity:
		ret.Message = ptr.Of(fmt.Sprintf("http code %d, invalid request: %s", r.StatusCode, string(data)))
	default:
		// try to unmarshal and if there are no 'message' or 'errors' fields, display the body as is,
		// the API is following a different convention
		err := json.Unmarshal(data, ret)
		if err != nil || (ret.Message == nil && ret.Errors == "") {
			ret.Message = ptr.Of(fmt.Sprintf("http code %d, response: %s", r.StatusCode, string(data)))
			return ret
		}
	}

	return ret
}
