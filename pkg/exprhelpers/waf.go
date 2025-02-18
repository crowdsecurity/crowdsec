package exprhelpers

import (
	"net/http"

	j4ah "github.com/crowdsecurity/crowdsec/pkg/appsec/ja4h"
)

// JA4H(req *http.Request) string
func JA4H(params ...any) (any, error) {
	req := params[0].(*http.Request)
	return j4ah.JA4H(req), nil
}
