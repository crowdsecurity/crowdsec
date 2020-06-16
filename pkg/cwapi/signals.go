package cwapi

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"

	log "github.com/sirupsen/logrus"
)

func (ctx *ApiCtx) AppendSignal(sig types.SignalOccurence) error {
	ctx.toPush = append(ctx.toPush, types.Event{Overflow: sig})
	log.Debugf("api append signal: adding new signal (cache size : %d): %+v", len(ctx.toPush), sig)
	return nil
}

func (ctx *ApiCtx) pushSignals() error {
	if len(ctx.toPush) == 0 {
		return nil
	}

	req, err := ctx.Http.New().Put(ctx.PushPath).BodyJSON(&ctx.toPush).Request()
	if err != nil {
		return fmt.Errorf("api push signal: HTTP request creation failed: %s", err)
	}
	log.Debugf("api push: URL: '%s'", req.URL)

	httpClient := http.Client{Timeout: 20 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("api push signal: API call failed : %s", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read body : %s", err)
	}
	log.Debugf("api push signal: HTTP Code: %+v | Body: %s \n", resp.StatusCode, string(body))
	if resp.StatusCode != 200 {
		if resp.StatusCode == 401 && !ctx.tokenExpired {
			log.Printf("api push signal: expired token, resigning to API")
			ctx.tokenExpired = true
			err := ctx.Signin()
			if err != nil {
				return err
			}
			log.Printf("api push signal: token renewed. Pushing signals")
			err = ctx.pushSignals()
			if err != nil {
				return fmt.Errorf("api push signal: unable to renew api session token: %s", err.Error())
			}
		} else {
			return fmt.Errorf("api push signal: return bad HTTP code (%d): %s", resp.StatusCode, string(body))
		}
	}
	if len(ctx.toPush) > 0 {
		log.Infof("api push signal: pushed %d signals successfully", len(ctx.toPush))
	}
	ctx.toPush = make([]types.Event, 0)
	ctx.tokenExpired = false
	return nil
}

func (ctx *ApiCtx) Flush() error {

	/*flag can be activated to dump to local file*/
	if ctx.DebugDump {
		log.Warningf("api flush: dumping api cache to ./api-dump.json")
		x, err := json.MarshalIndent(ctx.toPush, "", " ")
		if err != nil {
			return fmt.Errorf("api flush: failed to marshal data: %s", err)
		}
		if err := ioutil.WriteFile("./api-dump.json", x, 0755); err != nil {
			return fmt.Errorf("api flush: failed to write marshaled data : %s", err)
		}
	}

	//pretend we did stuff
	if ctx.Muted {
		return nil
	}
	if err := ctx.pushSignals(); err != nil {
		log.Errorf("api flush: fail to push signals: %s", err)
	}
	return nil
}

//This one is called on a regular basis (decided by init) and push stacked events to API
func (ctx *ApiCtx) pushLoop() error {
	log.Debugf("api push loop: running with a ticker every 2 minutes")
	ticker := time.NewTicker(2 * time.Minute)

	for {
		select {
		case <-ticker.C: //push data.
			if len(ctx.toPush) == 0 {
				log.Debugf("api push loop: nothing to push")
				continue
			}
			err := ctx.Flush()
			if err != nil {
				log.Errorf("api push loop: %s", err.Error())
			}
		case <-ctx.PusherTomb.Dying(): //we are being killed by main
			log.Infof("Killing api routine")
			return nil
		}
	}

}
