package apiclient

import (
	"context"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/trace"
)

type HeartBeatService service

func (h *HeartBeatService) Ping(ctx context.Context) (bool, *Response, error) {
	u := fmt.Sprintf("%s/heartbeat", h.client.URLPrefix)

	req, err := h.client.PrepareRequest(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, nil, err
	}

	resp, err := h.client.Do(ctx, req, nil)
	if err != nil {
		return false, resp, err
	}

	return true, resp, nil
}

func (h *HeartBeatService) StartHeartBeat(ctx context.Context) {
	go func() {
		defer trace.CatchPanic("crowdsec/apiClient/heartbeat")

		hbTimer := time.NewTicker(1 * time.Minute)

		for {
			select {
			case <-hbTimer.C:
				log.Debug("heartbeat: sending heartbeat")

				ok, resp, err := h.Ping(ctx)
				if err != nil {
					log.Errorf("heartbeat error: %s", err)
					continue
				}

				resp.Response.Body.Close()

				if resp.Response.StatusCode != http.StatusOK {
					log.Errorf("heartbeat unexpected return code: %d", resp.Response.StatusCode)
					continue
				}

				if !ok {
					log.Errorf("heartbeat returned false")
					continue
				}
			case <-ctx.Done():
				log.Debug("heartbeat: stopping")
				hbTimer.Stop()
				return
			}
		}
	}()
}
