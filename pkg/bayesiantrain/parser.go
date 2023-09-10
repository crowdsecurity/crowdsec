package bayesiantrain

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/antonmedv/expr/vm"
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

		fmt.Printf("Added log with filename : %v", name)
		s.Files = append(s.Files, name)
	}
	s.Parsersen = p

	return s
}

type parseResult struct {
	evt types.Event
	err error
}

func parsingRoutine(ctx parser.UnixParserCtx, Nodes []parser.Node, inputChan <-chan types.Event, outputChan chan<- parseResult) {

	for {
		ievt := <-inputChan
		evt, err := parser.Parse(ctx, ievt, Nodes)
		if err != nil {
			evt = ievt // We return the evt we fail to parse so collectingRoutine can add trace
		}
		outputChan <- parseResult{evt, err}
	}
}

func collectingRoutine(outputChan <-chan parseResult, resultChan chan<- LogEventStorage, messageChan <-chan int) {
	var storage LogEventStorage
	var bucket fakeBucket
	var ip string
	var exists bool

	hasReceivedTotal := false
	count := 0
	total := 0

	storage = LogEventStorage{
		ParsedIpEvents: make(map[string]fakeBucket),
		exprCache:      make(map[string]vm.Program),
		total:          0,
	}
LOOP:
	for {
		select {
		case total = <-messageChan:
			fmt.Println("Received total: %v", total)
			hasReceivedTotal = true
			if total == count {
				break LOOP
			}
		case res := <-outputChan:
			count += 1
			if count%10000 == 0 {
				fmt.Printf("\nLines processed : %v", count)
			}
			if res.err != nil {
				fmt.Printf("failed parsing %v", res.err)
				continue
			}
			ip, exists = res.evt.Meta["source_ip"]
			if !exists {
				fmt.Printf("no source ip found error, skipping")
				continue
			}
			bucket, exists = storage.ParsedIpEvents[ip]
			if !exists {
				bucket = fakeBucket{
					events: []types.Event{},
					leaky:  &leakybucket.Leaky{},
					label:  0,
				}
			}
			bucket.events = append(bucket.events, res.evt)
			storage.ParsedIpEvents[ip] = bucket
			if hasReceivedTotal && total == count {
				break LOOP
			}
		}
	}

	resultChan <- storage
}

func (p *ParserAndFileStorage) ParseLogs(routinesCount int) (LogEventStorage, error) {

	var scanner *bufio.Scanner
	var evt types.Event

	inputChan := make(chan types.Event, 10000)
	outputChan := make(chan parseResult, 10000)
	resultChan := make(chan LogEventStorage)
	messageChan := make(chan int)

	for i := 1; i <= routinesCount; i++ {
		go parsingRoutine(*p.Parsersen.Ctx, p.Parsersen.Nodes, inputChan, outputChan)
	}

	go collectingRoutine(outputChan, resultChan, messageChan)

	progress := 0
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
			inputChan <- evt

			progress += 1
			if progress%10000 == 0 {
				fmt.Printf("\nLines read : %v", progress)
			}
		}
	}
	messageChan <- progress
	fmt.Println("Sent total to collecting routine: %v", progress)
	storage := <-resultChan

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
