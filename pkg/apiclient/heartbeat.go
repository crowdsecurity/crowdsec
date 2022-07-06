package apiclient

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	tomb "gopkg.in/tomb.v2"
)

type HeartBeatService service

func (h *HeartBeatService) Ping(ctx context.Context) (bool, *Response, error) {

	u := fmt.Sprintf("%s/heartbeat", h.client.URLPrefix)

	req, err := h.client.NewRequest("GET", u, nil)
	if err != nil {
		return false, nil, err
	}

	resp, err := h.client.Do(ctx, req, nil)
	if err != nil {
		return false, resp, err
	}

	return true, resp, nil
}

func (h *HeartBeatService) StartHeartBeat(ctx context.Context, t *tomb.Tomb) {
	t.Go(func() error {
		defer types.CatchPanic("crowdsec/apiClient/heartbeat")
		hbTimer := time.NewTicker(1 * time.Minute)
		for {
			select {
			case <-hbTimer.C:
				log.Debug("heartbeat: sending heartbeat")
				ok, resp, err := h.Ping(ctx)
				if err != nil {
					log.Errorf("heartbeat error : %s", err)
					continue
				}
				resp.Response.Body.Close()
				if resp.Response.StatusCode != http.StatusOK {
					log.Errorf("heartbeat unexpected return code : %d", resp.Response.StatusCode)
					continue
				}
				if !ok {
					log.Errorf("heartbeat returned false")
					continue
				}
			case <-t.Dying():
				log.Debugf("heartbeat: stopping")
				hbTimer.Stop()
				return nil
			}
		}
	})
}
