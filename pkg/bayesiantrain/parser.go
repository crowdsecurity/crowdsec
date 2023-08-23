package bayesiantrain

import (
	"bufio"
	"fmt"
	"os"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type parserAndFileStorage struct {
	files     []string
	parsersen parser.Parsers
}

func (p *parserAndFileStorage) ParseLogs() (LogEventStorage, error) {

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
	for _, file := range p.files {
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
			evt, err = parser.Parse(*p.parsersen.Ctx, evt, p.parsersen.Nodes)

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
