package cwapi

import (
	"fmt"

	log "github.com/sirupsen/logrus"
)

func (ctx *ApiCtx) Enroll(userID string) error {
	toPush := map[string]string{"user_id": userID}
	jsonResp := &ApiResp{}
	errResp := &ApiResp{}

	resp, err := ctx.Http.New().Post(ctx.EnrollPath).BodyJSON(&toPush).Receive(jsonResp, errResp)
	if err != nil {
		return fmt.Errorf("api enroll: HTTP request creation failed: %s", err)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("api enroll: user '%s' return bad HTTP code (%d): %s", userID, resp.StatusCode, errResp.Message)
	}
	if jsonResp.Message == "" || jsonResp.Message != "OK" || jsonResp.StatusCode != 200 {
		return fmt.Errorf("api user enroll failed")
	}
	log.Printf("user '%s' is enrolled successfully", string(userID))
	return nil
}
