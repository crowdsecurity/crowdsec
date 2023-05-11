package parser

import (
	"errors"
	"regexp"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

var keyValuePattern = regexp.MustCompile(`\s*(?P<key>[^=\s]+)\s*=\s*(?:"(?P<quoted_value>[^"\\]*(?:\\.[^"\\]*)*)"|(?P<value>[^=\s]+))`)

func parseKV(field string, p *types.Event, ctx interface{}, plog *log.Entry) (map[string]string, error) {
	matches := keyValuePattern.FindAllStringSubmatch(p.Line.Raw, -1)
	if matches == nil {
		plog.Errorf("could not find any key/value pair in line")
		return nil, errors.New("invalid input format")
	}
	for _, match := range matches {
		key := ""
		value := ""
		for i, name := range keyValuePattern.SubexpNames() {
			if name == "key" {
				key = match[i]
			} else if name == "quoted_value" && match[i] != "" {
				value = match[i]
			} else if name == "value" && match[i] != "" {
				value = match[i]
			}
		}
		p.Unmarshaled[key] = value
	}
	plog.Tracef("unmarshaled KV: %+v", p.Unmarshaled)
	return nil, nil
}

func parseKVInit(cfg map[string]string) (interface{}, error) {
	return nil, nil
}
