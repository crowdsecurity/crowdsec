package main

import (
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/sqlite"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

//nolint:unused // pluginDB is the interface for sqlite output plugin
type pluginDB struct {
	CTX *sqlite.Context
}

func (p *pluginDB) Init(config map[string]string) error {
	var err error
	log.Debugf("sqlite config : %+v \n", config)
	p.CTX, err = sqlite.NewSQLite(config)

	if err != nil {
		return err
	}
	return nil
}

func (p *pluginDB) Delete(target string) (int, error) {
	nbDel, err := p.CTX.DeleteBan(target)
	if err != nil {
		return 0, err
	}
	log.Debugf("deleted '%d' entry from database", nbDel)
	return nbDel, nil
}

func (p *pluginDB) DeleteAll() error {
	err := p.CTX.DeleteAll()
	if err != nil {
		return err
	}
	return nil
}

func (p *pluginDB) Insert(sig types.SignalOccurence) error {
	err := p.CTX.WriteSignal(sig)
	if err != nil {
		return err
	}
	return nil
}

func (p *pluginDB) Flush() error {
	err := p.CTX.Flush()
	if err != nil {
		return err
	}

	return nil
}

func (p *pluginDB) ReadAT(timeAT time.Time) ([]map[string]string, error) {
	ret, err := p.CTX.GetBansAt(timeAT)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

//nolint:deadcode,unused // New is used by the plugin system
func New() interface{} {
	return &pluginDB{}
}

// empty main function is mandatory since we are in a main package
func main() {}
