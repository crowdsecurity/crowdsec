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
		plog.Errorf("unmarshal: %s", err)
		return nil, err
	}
	plog.Tracef("unmarshaled: %+v", p.Unmarshaled)
	return nil, nil
}

func unmarshalXML(field string, p *types.Event, ctx interface{}, plog *log.Entry) (map[string]string, error) {
	err := xml.Unmarshal([]byte(p.Line.Raw), &p.Unmarshaled)
	if err != nil {
		plog.Errorf("unmarshal: %s", err)
		return nil, err
	}
	plog.Tracef("unmarshaled: %+v", p.Unmarshaled)
	return nil, nil
}

func unmarshalInit(cfg map[string]string) (interface{}, error) {
	return nil, nil
}
