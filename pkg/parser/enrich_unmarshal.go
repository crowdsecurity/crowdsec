package parser

import (
	"encoding/json"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

func unmarshalJSON(field string, p *types.Event, ctx interface{}, plog *log.Entry) (map[string]string, error) {
	if p.Unmarshaled.JSON == nil {
		p.Unmarshaled.JSON = make(map[string]interface{})
	}
	err := json.Unmarshal([]byte(p.Line.Raw), &p.Unmarshaled.JSON)
	if err != nil {
		plog.Errorf("could not unmarshal JSON: %s", err)
		return nil, err
	}
	plog.Tracef("unmarshaled JSON: %+v", p.Unmarshaled)
	return nil, nil
}

func unmarshalInit(cfg map[string]string) (interface{}, error) {
	return nil, nil
}
