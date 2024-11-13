package parser

import (
	"encoding/json"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func unmarshalJSON(field string, p *types.Event, plog *log.Entry) (map[string]string, error) {
	err := json.Unmarshal([]byte(p.Line.Raw), &p.Unmarshaled)
	if err != nil {
		plog.Errorf("could not parse JSON: %s", err)
		return nil, err
	}
	plog.Tracef("unmarshaled JSON: %+v", p.Unmarshaled)
	return nil, nil
}
