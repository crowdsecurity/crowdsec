package cwapi

import (
	"fmt"
	"io/ioutil"

	log "github.com/sirupsen/logrus"
)

func (ctx *ApiCtx) PullTop() ([]map[string]string, error) {
	top := &PullResp{}
	resp, err := ctx.Http.Get(ctx.PullPath).ReceiveSuccess(top)
	if err != nil {
		return nil, fmt.Errorf("api pull: HTTP request creation failed: %s", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("api pull: unable to read API response body: '%s'", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("api pull: return bad HTTP code (%d): %s", resp.StatusCode, string(body))
	}

	log.Debugf("api pull: response : %+v", top.Body)
	return top.Body, nil
}
