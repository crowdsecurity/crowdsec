package bayesiantrain

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type ParserAndFileStorage struct {
	Files     []string
	Parsersen *parser.Parsers
}

func LoadParsers(input, patterns, files string) ParserAndFileStorage {

	s := ParserAndFileStorage{}
	p := &parser.Parsers{}
	p.Ctx, _ = parser.Init(map[string]interface{}{
		"patterns": patterns,
		"data":     "",
	})
	for _, name := range strings.Split(input, ",") {

		p.StageFiles = append(p.StageFiles, parser.Stagefile{
			Filename: name,
			Stage:    "s01-parse",
		})
	}
	p.Nodes, _ = parser.LoadStages(p.StageFiles, p.Ctx, p.EnricherCtx)

	for _, name := range strings.Split(files, ",") {

		s.Files = append(s.Files, name)
	}
	s.Parsersen = p

	return s
}

func (p *ParserAndFileStorage) ParseLogs() (LogEventStorage, error) {

	var storage LogEventStorage
	var scanner *bufio.Scanner
	var evt types.Event
	var bucket fakeBucket
	var ip string
	var exists bool

	storage = LogEventStorage{
		ParsedIpEvents: make(map[string]fakeBucket),
		total:          0,
	}
	for _, file := range p.Files {
		fd, err := os.Open(file)

		if err != nil {
			return LogEventStorage{}, fmt.Errorf("failed opening %s: %w", file, err)
		}
		defer fd.Close()
		scanner = bufio.NewScanner(fd)

		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			if scanner.Text() == "" {
				continue
			}
			l := types.Line{
				Raw:     scanner.Text(),
				Time:    time.Now().UTC(),
				Src:     file,
				Process: true,
			}

			evt = types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: types.TIMEMACHINE}
			evt, err = parser.Parse(*p.Parsersen.Ctx, evt, p.Parsersen.Nodes)

			if err != nil {
				return LogEventStorage{}, fmt.Errorf("failed parsing line %s: %w", l.Raw, err)
			}

			ip, exists = evt.Meta["source_ip"]
			if !exists {
				return LogEventStorage{}, fmt.Errorf("no source ip found in evt %s: ", l.Raw)
			}

			bucket, exists = storage.ParsedIpEvents[ip]
			if !exists {
				bucket = fakeBucket{
					events: []types.Event{},
					leaky:  &leakybucket.Leaky{},
					label:  0,
				}
			}
			bucket.events = append(bucket.events, evt)
			storage.ParsedIpEvents[ip] = bucket
		}

	}

	return storage, nil
}

func CreateFakeConfig(configDir string, dataDir string) (cConfig *csconfig.Config) {

	svcConfig := csconfig.CrowdsecServiceCfg{
		ConfigDir: configDir,
		DataDir:   dataDir,
	}
	config := csconfig.Config{
		Crowdsec:   &svcConfig,
		Prometheus: nil,
	}

	return &config
}
