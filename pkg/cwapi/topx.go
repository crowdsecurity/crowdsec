package cwapi

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

func (ctx *ApiCtx) PullTop() ([]map[string]string, error) {
	req, err := ctx.Http.New().Get(ctx.PullPath).Request()
	if err != nil {
		return nil, fmt.Errorf("api pull: HTTP request creation failed: %s", err)
	}
	log.Debugf("api pull: URL: '%s'", req.URL)
	httpClient := http.Client{Timeout: 20 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("api pull: API call failed : %s", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("api pull: unable to read API response body: '%s'", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("api pull: return bad HTTP code (%d): %s", resp.StatusCode, string(body))
	}

	top := PullResp{}
	err = json.Unmarshal([]byte(body), &top)
	if err != nil {
		return nil, fmt.Errorf("api pull: unable to unmarshall api response '%s': %s", string(body), err.Error())
	}

	log.Debugf("api pull: response : %+v", top.Body)
	return top.Body, nil
}
