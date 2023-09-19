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
	_ "net/http/pprof"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/goombaio/namegenerator"
	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
)

var seed namegenerator.Generator = namegenerator.NewNameGenerator(time.Now().UTC().UnixNano())

/*
 identify generic component to alter maps, smartfilters ? (static, conditional static etc.)
*/

type Stagefile struct {
	Filename string `yaml:"filename"`
	Stage    string `yaml:"stage"`
}

func LoadStages(stageFiles []Stagefile, pctx *UnixParserCtx, ectx EnricherCtx) ([]Node, error) {
	var nodes []Node
	tmpstages := make(map[string]bool)
	pctx.Stages = []string{}

	for _, stageFile := range stageFiles {
		if !strings.HasSuffix(stageFile.Filename, ".yaml") && !strings.HasSuffix(stageFile.Filename, ".yml") {
			log.Warningf("skip non yaml : %s", stageFile.Filename)
			continue
		}
		log.Debugf("loading parser file '%s'", stageFile)
		st, err := os.Stat(stageFile.Filename)
		if err != nil {
			return nil, fmt.Errorf("failed to stat %s : %v", stageFile, err)
		}
		if st.IsDir() {
			continue
		}
		yamlFile, err := os.Open(stageFile.Filename)
		if err != nil {
			return nil, fmt.Errorf("can't access parsing configuration file %s : %s", stageFile.Filename, err)
		}
		//process the yaml
		dec := yaml.NewDecoder(yamlFile)
		dec.SetStrict(true)
		nodesCount := 0
		for {
			node := Node{}
			node.OnSuccess = "continue" //default behavior is to continue
			err = dec.Decode(&node)
			if err != nil {
				if errors.Is(err, io.EOF) {
					log.Tracef("End of yaml file")
					break
				}
				log.Fatalf("Error decoding parsing configuration file '%s': %v", stageFile.Filename, err)
			}

			//check for empty bucket
			if node.Name == "" && node.Description == "" && node.Author == "" {
				log.Infof("Node in %s has no name, author or description. Skipping.", stageFile.Filename)
				continue
			}
			//check compat
			if node.FormatVersion == "" {
				log.Tracef("no version in %s, assuming '1.0'", node.Name)
				node.FormatVersion = "1.0"
			}
			ok, err := cwversion.Satisfies(node.FormatVersion, cwversion.Constraint_parser)
			if err != nil {
				log.Fatalf("Failed to check version : %s", err)
			}
			if !ok {
				log.Errorf("%s : %s doesn't satisfy parser format %s, skip", node.Name, node.FormatVersion, cwversion.Constraint_parser)
				continue
			}

			node.Stage = stageFile.Stage
			if _, ok := tmpstages[stageFile.Stage]; !ok {
				tmpstages[stageFile.Stage] = true
			}
			//compile the node : grok pattern and expression
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
					log.Error(err)
				}
				if data.Type == "regexp" { //cache only makes sense for regexp
					exprhelpers.RegexpCacheInit(data.DestPath, *data)
				}
			}

			nodes = append(nodes, node)
			nodesCount++
		}
		log.WithFields(log.Fields{"file": stageFile.Filename, "stage": stageFile.Stage}).Infof("Loaded %d parser nodes", nodesCount)
	}

	for k := range tmpstages {
		pctx.Stages = append(pctx.Stages, k)
	}
	sort.Strings(pctx.Stages)
	log.Infof("Loaded %d nodes from %d stages", len(nodes), len(pctx.Stages))

	return nodes, nil
}
