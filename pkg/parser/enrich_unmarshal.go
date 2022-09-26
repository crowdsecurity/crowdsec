package parser

import (
	"encoding/json"
	"encoding/xml"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

func unmarshalJSON(field string, p *types.Event, ctx interface{}, plog *log.Entry) (map[string]string, error) {
	err := json.Unmarshal([]byte(p.Line.Raw), &p.Unmarshaled)
	if err != nil {
		plog.Errorf("could not unmarshal JSON: %s", err)
		return nil, err
	}
	plog.Tracef("unmarshaled JSON: %+v", p.Unmarshaled)
	return nil, nil
}

func unmarshalXML(field string, p *types.Event, ctx interface{}, plog *log.Entry) (map[string]string, error) {
	err := xml.Unmarshal([]byte(p.Line.Raw), &p.Unmarshaled)
	if err != nil {
		plog.Errorf("could not unmarshal XML: %s", err)
		return nil, err
	}
	plog.Tracef("unmarshaled XML: %+v", p.Unmarshaled)
	return nil, nil
}

func unmarshalInit(cfg map[string]string) (interface{}, error) {
	return nil, nil
}
