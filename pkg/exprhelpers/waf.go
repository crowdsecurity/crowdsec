package exprhelpers

import (
	"net/http"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/ja4h"
)

// JA4H(req *http.Request) string
func JA4H(params ...any) (any, error) {
	req := params[0].(*http.Request)
	return ja4h.JA4H(req), nil
}
