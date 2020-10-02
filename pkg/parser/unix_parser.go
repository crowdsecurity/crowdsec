package parser

import (
	"io/ioutil"

	"github.com/logrusorgru/grokky"
	log "github.com/sirupsen/logrus"
)

type UnixParserCtx struct {
	Grok       grokky.Host
	Stages     []string
	Profiling  bool
	DataFolder string
}

func Init(c map[string]interface{}) (*UnixParserCtx, error) {
	r := UnixParserCtx{}
	r.Grok = grokky.NewBase()
	files, err := ioutil.ReadDir(c["patterns"].(string))
	if err != nil {
		return nil, err
	}
	r.DataFolder = c["data"].(string)
	for _, f := range files {
		if err := r.Grok.AddFromFile(c["patterns"].(string) + f.Name()); err != nil {
			log.Errorf("failed to load pattern %s : %v", f.Name(), err)
			return nil, err
		}
	}
	log.Debugf("Loaded %d pattern files", len(files))
	return &r, nil
}
