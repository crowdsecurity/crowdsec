package cwapi

import (
	"fmt"

	log "github.com/sirupsen/logrus"
)

func (ctx *ApiCtx) PullTop() ([]map[string]string, error) {
	top := &PullResp{}
	resp, err := ctx.Http.New().Get(ctx.PullPath).ReceiveSuccess(top)
	if err != nil {
		return nil, fmt.Errorf("api pull: HTTP request creation failed: %s", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("api pull: return bad HTTP code (%d)", resp.StatusCode)
	}

	log.Debugf("api pull: response : %+v", top.Body)
	return top.Body, nil
}
