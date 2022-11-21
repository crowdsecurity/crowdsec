package hubtest

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	log "github.com/sirupsen/logrus"
)

type ParserCoverage struct {
	Parser     string
	TestsCount int
	PresentIn  map[string]bool //poorman's set
}

type ScenarioCoverage struct {
	Scenario   string
	TestsCount int
	PresentIn  map[string]bool
}

func (h *HubTest) GetParsersCoverage() ([]ParserCoverage, error) {
	var coverage []ParserCoverage
	if _, ok := h.HubIndex.Data[cwhub.PARSERS]; !ok {
		return coverage, fmt.Errorf("no parsers in hub index")
	}
	//populate from hub, iterate in alphabetical order
	var pkeys []string
	for pname := range h.HubIndex.Data[cwhub.PARSERS] {
		pkeys = append(pkeys, pname)
	}
	sort.Strings(pkeys)
	for _, pname := range pkeys {
		coverage = append(coverage, ParserCoverage{
			Parser:     pname,
			TestsCount: 0,
			PresentIn:  make(map[string]bool),
		})
	}

	//parser the expressions a-la-oneagain
	passerts, err := filepath.Glob(".tests/*/parser.assert")
	if err != nil {
		return coverage, fmt.Errorf("while find parser asserts : %s", err)
	}
	for _, assert := range passerts {
		file, err := os.Open(assert)
		if err != nil {
			return coverage, fmt.Errorf("while reading %s : %s", assert, err)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			assertLine := regexp.MustCompile(`^results\["[^"]+"\]\["(?P<parser>[^"]+)"\]\[[0-9]+\]\.Evt\..*`)
			line := scanner.Text()
			log.Debugf("assert line : %s", line)
			match := assertLine.FindStringSubmatch(line)
			if len(match) == 0 {
				log.Debugf("%s doesn't match", line)
				continue
			}
			sidx := assertLine.SubexpIndex("parser")
			capturedParser := match[sidx]
			for idx, pcover := range coverage {
				if pcover.Parser == capturedParser {
					coverage[idx].TestsCount++
					coverage[idx].PresentIn[assert] = true
					continue
				}
				parserNameSplit := strings.Split(pcover.Parser, "/")
				parserNameOnly := parserNameSplit[len(parserNameSplit)-1]
				if parserNameOnly == capturedParser {
					coverage[idx].TestsCount++
					coverage[idx].PresentIn[assert] = true
					continue
				}
				capturedParserSplit := strings.Split(capturedParser, "/")
				capturedParserName := capturedParserSplit[len(capturedParserSplit)-1]
				if capturedParserName == parserNameOnly {
					coverage[idx].TestsCount++
					coverage[idx].PresentIn[assert] = true
					continue
				}
				if capturedParserName == parserNameOnly+"-logs" {
					coverage[idx].TestsCount++
					coverage[idx].PresentIn[assert] = true
					continue
				}
			}
		}
		file.Close()
	}
	return coverage, nil
}

func (h *HubTest) GetScenariosCoverage() ([]ScenarioCoverage, error) {
	var coverage []ScenarioCoverage
	if _, ok := h.HubIndex.Data[cwhub.SCENARIOS]; !ok {
		return coverage, fmt.Errorf("no scenarios in hub index")
	}
	//populate from hub, iterate in alphabetical order
	var pkeys []string
	for scenarioName := range h.HubIndex.Data[cwhub.SCENARIOS] {
		pkeys = append(pkeys, scenarioName)
	}
	sort.Strings(pkeys)
	for _, scenarioName := range pkeys {
		coverage = append(coverage, ScenarioCoverage{
			Scenario:   scenarioName,
			TestsCount: 0,
			PresentIn:  make(map[string]bool),
		})
	}

	//parser the expressions a-la-oneagain
	passerts, err := filepath.Glob(".tests/*/scenario.assert")
	if err != nil {
		return coverage, fmt.Errorf("while find scenario asserts : %s", err)
	}
	for _, assert := range passerts {
		file, err := os.Open(assert)
		if err != nil {
			return coverage, fmt.Errorf("while reading %s : %s", assert, err)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			assertLine := regexp.MustCompile(`^results\[[0-9]+\].Overflow.Alert.GetScenario\(\) == "(?P<scenario>[^"]+)"`)
			line := scanner.Text()
			log.Debugf("assert line : %s", line)
			match := assertLine.FindStringSubmatch(line)
			if len(match) == 0 {
				log.Debugf("%s doesn't match", line)
				continue
			}
			sidx := assertLine.SubexpIndex("scenario")
			scanner_name := match[sidx]
			for idx, pcover := range coverage {
				if pcover.Scenario == scanner_name {
					coverage[idx].TestsCount++
					coverage[idx].PresentIn[assert] = true
					continue
				}
				scenarioNameSplit := strings.Split(pcover.Scenario, "/")
				scenarioNameOnly := scenarioNameSplit[len(scenarioNameSplit)-1]
				if scenarioNameOnly == scanner_name {
					coverage[idx].TestsCount++
					coverage[idx].PresentIn[assert] = true
					continue
				}
				fixedProbingWord := strings.ReplaceAll(pcover.Scenario, "probbing", "probing")
				fixedProbingAssert := strings.ReplaceAll(scanner_name, "probbing", "probing")
				if fixedProbingWord == fixedProbingAssert {
					coverage[idx].TestsCount++
					coverage[idx].PresentIn[assert] = true
					continue
				}
				if fmt.Sprintf("%s-detection", pcover.Scenario) == scanner_name {
					coverage[idx].TestsCount++
					coverage[idx].PresentIn[assert] = true
					continue
				}
				if fmt.Sprintf("%s-detection", fixedProbingWord) == fixedProbingAssert {
					coverage[idx].TestsCount++
					coverage[idx].PresentIn[assert] = true
					continue
				}
			}
		}
		file.Close()
	}
	return coverage, nil
}
