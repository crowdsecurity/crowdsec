package cwapi

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

func (ctx *ApiCtx) Enroll(userID string) error {
	toPush := map[string]string{"user_id": userID}

	req, err := ctx.Http.New().Post(ctx.EnrollPath).BodyJSON(&toPush).Request()
	if err != nil {
		return fmt.Errorf("api enroll: HTTP request creation failed: %s", err)
	}
	log.Debugf("api enroll: URL: '%s'", req.URL)
	httpClient := http.Client{Timeout: 20 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("api enroll: API call failed : %s", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("api enroll: unable to read API response body: '%s'", err)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("api enroll: user '%s' return bad HTTP code (%d): %s", userID, resp.StatusCode, string(body))
	}
	log.Printf("user '%s' is enrolled successfully", string(userID))
	return nil
}
