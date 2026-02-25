package parser

/*
 This file contains
 - the runtime definition of parser
 - the compilation/parsing routines of parser configuration
*/

import (
	"errors"
	"fmt"
	"io"
	// enable profiling
	_ "net/http/pprof"
	"os"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion/constraint"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
)

/*
 identify generic component to alter maps, smartfilters ? (static, conditional static etc.)
*/

type Stagefile struct {
	Filename string `yaml:"filename"`
	Stage    string `yaml:"stage"`
}

func LoadStages(stageFiles []Stagefile, pctx *UnixParserCtx, ectx EnricherCtx) ([]Node, error) {
	var allNodes []Node

	tmpStages := make(map[string]bool)
	pctx.Stages = []string{}

	for _, sf := range stageFiles {
		nodes, err := processStageFile(sf, pctx, ectx)
		if err != nil {
			return nil, err
		}

		for _, n := range nodes { //nolint:gocritic // rangeValCopy
			allNodes = append(allNodes, n)
			tmpStages[n.Stage] = true
		}
	}

	for k := range tmpStages {
		pctx.Stages = append(pctx.Stages, k)
	}

	sort.Strings(pctx.Stages)
	log.Infof("Loaded %d nodes from %d stages", len(allNodes), len(pctx.Stages))

	return allNodes, nil
}

func processStageFile(stageFile Stagefile, pctx *UnixParserCtx, ectx EnricherCtx) ([]Node, error) {
	if !strings.HasSuffix(stageFile.Filename, ".yaml") && !strings.HasSuffix(stageFile.Filename, ".yml") {
		log.Warningf("skip non yaml : %s", stageFile.Filename)
		return nil, nil
	}

	log.Debugf("loading parser file '%s'", stageFile)

	st, err := os.Stat(stageFile.Filename)
	if err != nil {
		return nil, fmt.Errorf("failed to stat %s : %v", stageFile, err)
	}

	if st.IsDir() {
		return nil, nil
	}

	yamlFile, err := os.Open(stageFile.Filename)
	if err != nil {
		return nil, fmt.Errorf("can't access parsing configuration file %s : %s", stageFile.Filename, err)
	}
	defer yamlFile.Close()
	// process the yaml
	dec := yaml.NewDecoder(yamlFile)
	dec.SetStrict(true)

	var nodes []Node

	nodesCount := 0

	for {
		node := Node{}
		node.OnSuccess = "continue" // default behavior is to continue

		if err = dec.Decode(&node); err != nil {
			if errors.Is(err, io.EOF) {
				log.Tracef("End of yaml file")
				break
			}

			return nil, fmt.Errorf("error decoding parsing configuration file '%s': %v", stageFile.Filename, err)
		}

		// check for empty bucket
		if node.Name == "" && node.Description == "" && node.Author == "" {
			log.Infof("Node in %s has no name, author or description. Skipping.", stageFile.Filename)
			continue
		}

		// check compat
		if node.FormatVersion == "" {
			log.Tracef("no version in %s, assuming '1.0'", node.Name)
			node.FormatVersion = "1.0"
		}

		ok, err := constraint.Satisfies(node.FormatVersion, constraint.Parser)
		if err != nil {
			return nil, fmt.Errorf("failed to check version : %s", err)
		}

		if !ok {
			log.Errorf("%s : %s doesn't satisfy parser format %s, skip", node.Name, node.FormatVersion, constraint.Parser)
			continue
		}

		node.Stage = stageFile.Stage
		// compile the node : grok pattern and expression

		err = node.compile(pctx, ectx)
		if err != nil {
			if node.Name != "" {
				return nil, fmt.Errorf("failed to compile node '%s' in '%s' : %s", node.Name, stageFile.Filename, err)
			}

			return nil, fmt.Errorf("failed to compile node in '%s' : %s", stageFile.Filename, err)
		}
		/* if the stage is empty, the node is empty, it's a trailing entry in users yaml file */
		if node.Stage == "" {
			continue
		}

		for _, data := range node.Data {
			err = exprhelpers.FileInit(pctx.DataFolder, data.DestPath, data.Type)
			if err != nil {
				log.Error(err.Error())
			}

			if data.Type == "regexp" { // cache only makes sense for regexp
				if err = exprhelpers.RegexpCacheInit(data.DestPath, *data); err != nil {
					log.Error(err.Error())
				}
			}
		}

		nodes = append(nodes, node)
		nodesCount++
	}

	log.WithFields(log.Fields{"file": stageFile.Filename, "stage": stageFile.Stage}).Infof("Loaded %d parser nodes", nodesCount)

	return nodes, nil
}
