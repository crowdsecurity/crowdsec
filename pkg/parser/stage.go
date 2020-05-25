package parser

/*
 This file contains
 - the runtime definition of parser
 - the compilation/parsing routines of parser configuration
*/

import (
	//"fmt"

	"fmt"
	"io"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion"

	log "github.com/sirupsen/logrus"

	"github.com/goombaio/namegenerator"
	yaml "gopkg.in/yaml.v2"
)

var seed namegenerator.Generator = namegenerator.NewNameGenerator(time.Now().UTC().UnixNano())

/*
 identify generic component to alter maps, smartfilters ? (static, conditional static etc.)
*/

type Stagefile struct {
	Filename string `yaml:"filename"`
	Stage    string `yaml:"stage"`
}

func LoadStages(stageFiles []Stagefile, pctx *UnixParserCtx) ([]Node, error) {
	var nodes []Node
	tmpstages := make(map[string]bool)
	pctx.Stages = []string{}

	for _, stageFile := range stageFiles {
		if !strings.HasSuffix(stageFile.Filename, ".yaml") {
			log.Warningf("skip non yaml : %s", stageFile.Filename)
			continue
		}
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
			node.OnSuccess = "continue" //default behaviour is to continue
			err = dec.Decode(&node)
			if err != nil {
				if err == io.EOF {
					log.Tracef("End of yaml file")
					break
				}
				log.Fatalf("Error decoding parsing configuration file '%s': %v", stageFile.Filename, err)
			}

			//check for empty bucket
			if node.Name == "" && node.Description == "" && node.Author == "" {
				log.Infof("Node has no name,author or description. Skipping.")
				continue
			}
			//check compat
			if node.FormatVersion == "" {
				log.Debugf("no version in %s, assuming '1.0'", stageFile.Filename)
				node.FormatVersion = "1.0"
			}
			ok, err := cwversion.Statisfies(node.FormatVersion, cwversion.Constraint_parser)
			if err != nil {
				log.Fatalf("Failed to check version : %s", err)
			}
			if !ok {
				log.Errorf("%s doesn't satisfy parser format %s, skip", node.FormatVersion, cwversion.Constraint_parser)
				continue
			}

			node.Stage = stageFile.Stage
			if _, ok := tmpstages[stageFile.Stage]; !ok {
				tmpstages[stageFile.Stage] = true
			}
			//compile the node : grok pattern and expression
			err = node.compile(pctx)
			if err != nil {
				if node.Name != "" {
					return nil, fmt.Errorf("failed to compile node '%s' in '%s' : %s", node.Name, stageFile.Filename, err.Error())
				}
				return nil, fmt.Errorf("failed to compile node in '%s' : %s", stageFile.Filename, err.Error())
			}
			/* if the stage is empty, the node is empty, it's a trailing entry in users yaml file */
			if node.Stage == "" {
				continue
			}
			nodes = append(nodes, node)
			nodesCount++
		}
		log.WithFields(log.Fields{"file": stageFile.Filename}).Infof("Loaded %d parser nodes", nodesCount)
	}

	for k := range tmpstages {
		pctx.Stages = append(pctx.Stages, k)
	}
	sort.Strings(pctx.Stages)
	log.Infof("Stages loaded: %+v", pctx.Stages)
	return nodes, nil
}

func LoadStageDir(dir string, pctx *UnixParserCtx) ([]Node, error) {

	var files []Stagefile

	m, err := filepath.Glob(dir + "/*/*")
	if err != nil {
		return nil, fmt.Errorf("unable to find configs in '%s' : %v", dir, err)
	}
	for _, f := range m {
		tmp := Stagefile{}
		tmp.Filename = f
		//guess stage : (prefix - file).split('/')[0]
		stages := strings.Split(f, "/")
		stage := stages[len(stages)-2]
		tmp.Stage = stage
		files = append(files, tmp)
	}
	return LoadStages(files, pctx)
}
