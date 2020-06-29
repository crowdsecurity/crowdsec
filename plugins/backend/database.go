package main

import (
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

//nolint:unused // pluginDB is the interface for database output plugin
type pluginDB struct {
	CTX *database.Context
}

func (p *pluginDB) Shutdown() error {
	p.CTX.PusherTomb.Kill(nil)
	if err := p.CTX.PusherTomb.Wait(); err != nil {
		return fmt.Errorf("DB shutdown error : %s", err)
	}

	return nil
}

func (p *pluginDB) Init(config map[string]string) error {
	var err error
	log.Debugf("database config : %+v \n", config)
	p.CTX, err = database.NewDatabase(config)

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
