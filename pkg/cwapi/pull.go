package cwapi

import (
	"fmt"

	log "github.com/sirupsen/logrus"
)

func (ctx *ApiCtx) PullTop() ([]map[string]string, error) {
	top := &PullResp{}
	errResp := &ApiResp{}

	resp, err := ctx.Http.New().Get(ctx.PullPath).Receive(top, errResp)
	if err != nil {
		return nil, fmt.Errorf("api pull: HTTP request creation failed: %s", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("api pull: return bad HTTP code (%d): %s", resp.StatusCode, errResp.Message)
	}

	log.Debugf("api pull: response : %+v", top.Body)
	return top.Body, nil
}
