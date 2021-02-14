package acquisition

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	tomb "gopkg.in/tomb.v2"
)

func TestConfigLoading(t *testing.T) {
	//bad filename
	cfg := csconfig.CrowdsecServiceCfg{
		AcquisitionFiles: []string{"./tests/xxx.yaml"},
	}
	_, err := LoadAcquisitionFromFile(&cfg)
	assert.Contains(t, fmt.Sprintf("%s", err), "can't open ./tests/xxx.yaml: open ./tests/xxx.yaml: no such file or directory")
	//bad config file
	cfg = csconfig.CrowdsecServiceCfg{
		AcquisitionFiles: []string{"./tests/test.log"},
	}
	_, err = LoadAcquisitionFromFile(&cfg)
	assert.Contains(t, fmt.Sprintf("%s", err), "failed to yaml decode ./tests/test.log: yaml: unmarshal errors")
	//correct config file
	cfg = csconfig.CrowdsecServiceCfg{
		AcquisitionFiles: []string{"./tests/acquis_test.yaml"},
	}
	srcs, err := LoadAcquisitionFromFile(&cfg)
	if err != nil {
		t.Fatalf("unexpected error : %s", err)
	}
	assert.Equal(t, len(srcs), 1)
}

func TestDataSourceConfigure(t *testing.T) {
	tests := []struct {
		cfg DataSourceCfg
		//tombState
		config_error string
		read_error   string
		tomb_error   string
		lines        int
	}{
		{ //missing filename(s)
			cfg: DataSourceCfg{
				Mode: CAT_MODE,
			},
			config_error: "empty filename(s) and journalctl filter, malformed datasource",
		},
		{ //missing filename(s)
			cfg: DataSourceCfg{
				Mode: TAIL_MODE,
			},
			config_error: "empty filename(s) and journalctl filter, malformed datasource",
		},
		{ //bad mode(s)
			cfg: DataSourceCfg{
				Filename: "./tests/test.log",
				Mode:     "ratata",
			},
			config_error: "configuring file datasource: unknown mode ratata for file acquisition",
		},
		{ //ok test
			cfg: DataSourceCfg{
				Mode:     CAT_MODE,
				Filename: "./tests/test.log",
			},
		},
		{ //missing mode, default to CAT_MODE
			cfg: DataSourceCfg{
				Filename: "./tests/test.log",
			},
		},
		{ //ok test for journalctl
			cfg: DataSourceCfg{
				Mode:              CAT_MODE,
				JournalctlFilters: []string{"-test.run=TestSimJournalctlCatOneLine", "--"},
			},
		},
	}

	for tidx, test := range tests {

		srcs, err := DataSourceConfigure(test.cfg)
		if test.config_error != "" {
			assert.Contains(t, fmt.Sprintf("%s", err), test.config_error)
			log.Infof("expected config error ok : %s", test.config_error)
			continue
		} else {
			if err != nil {
				t.Fatalf("%d/%d unexpected config error %s", tidx, len(tests), err)
			}
		}

		//check we got the expected mode
		if tests[tidx].cfg.Mode == "" {
			tests[tidx].cfg.Mode = TAIL_MODE
		}
		assert.Equal(t, srcs.Mode(), tests[tidx].cfg.Mode)

		out := make(chan types.Event)
		tomb := tomb.Tomb{}

		go func() {
			err = StartAcquisition([]DataSource{srcs}, out, &tomb)
			if test.read_error != "" {
				assert.Contains(t, fmt.Sprintf("%s", err), test.read_error)
				log.Infof("expected read error ok : %s", test.read_error)
			} else {
				if err != nil {
					log.Fatalf("%d/%d unexpected read error %s", tidx, len(tests), err)
				}
			}
		}()

		log.Printf("kill iiittt")
		//we're actually not interested in the result :)
		tomb.Kill(nil)
		time.Sleep(1 * time.Second)

		if test.tomb_error != "" {
			assert.Contains(t, fmt.Sprintf("%s", tomb.Err()), test.tomb_error)
			log.Infof("expected tomb error ok : %s", test.read_error)
			continue
		} else {
			if tomb.Err() != nil {
				t.Fatalf("%d/%d unexpected tomb error %s", tidx, len(tests), tomb.Err())
			}
		}

	}

}
