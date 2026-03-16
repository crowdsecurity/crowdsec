package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/grokky"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/fflag"
)

type UnixParserCtx struct {
	Grok       grokky.Host
	Stages     []string
	Profiling  bool
	DataFolder string
}

type Parsers struct {
	Ctx             *UnixParserCtx
	PovfwCtx        *UnixParserCtx
	StageFiles      []Stagefile
	PovfwStageFiles []Stagefile
	Nodes           []Node
	Povfwnodes      []Node
	EnricherCtx     EnricherCtx
}

func NewUnixParserCtx(patternDir string, dataDir string) (*UnixParserCtx, error) {
	r := UnixParserCtx{}
	r.Grok = grokky.NewBase()
	r.Grok.UseRe2 = fflag.Re2GrokSupport.IsEnabled()

	files, err := os.ReadDir(patternDir)
	if err != nil {
		return nil, err
	}

	r.DataFolder = dataDir

	for _, file := range files {
		if strings.Contains(file.Name(), ".") || file.IsDir() {
			continue
		}

		if err := r.Grok.AddFromFile(filepath.Join(patternDir, file.Name())); err != nil {
			log.Errorf("failed to load pattern %s: %v", file.Name(), err)
			return nil, err
		}
	}

	log.Debugf("Loaded %d pattern files", len(files))

	return &r, nil
}

// Return new parsers
// nodes and povfwnodes are already initialized in parser.LoadStages
func NewParsers(hub *cwhub.Hub) *Parsers {
	parsers := &Parsers{
		Ctx:             &UnixParserCtx{},
		PovfwCtx:        &UnixParserCtx{},
		StageFiles:      make([]Stagefile, 0),
		PovfwStageFiles: make([]Stagefile, 0),
	}

	for _, itemType := range []string{cwhub.PARSERS, cwhub.POSTOVERFLOWS} {
		for _, hubParserItem := range hub.GetInstalledByType(itemType, false) {
			stagefile := Stagefile{
				Filename: hubParserItem.State.LocalPath,
				Stage:    hubParserItem.Stage,
			}

			if itemType == cwhub.PARSERS {
				parsers.StageFiles = append(parsers.StageFiles, stagefile)
			}

			if itemType == cwhub.POSTOVERFLOWS {
				parsers.PovfwStageFiles = append(parsers.PovfwStageFiles, stagefile)
			}
		}
	}

	sort.Slice(parsers.StageFiles, func(i, j int) bool {
		return parsers.StageFiles[i].Filename < parsers.StageFiles[j].Filename
	})

	sort.Slice(parsers.PovfwStageFiles, func(i, j int) bool {
		return parsers.PovfwStageFiles[i].Filename < parsers.PovfwStageFiles[j].Filename
	})

	return parsers
}

func LoadParsers(cConfig *csconfig.Config, hub *cwhub.Hub) (*Parsers, error) {
	var err error

	patternDir := cConfig.ConfigPaths.PatternDir
	log.Infof("Loading grok library %s", patternDir)

	parsers := NewParsers(hub)

	/* load base regexps for two grok parsers */
	parsers.Ctx, err = NewUnixParserCtx(patternDir, cConfig.ConfigPaths.DataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load parser patterns: %w", err)
	}

	parsers.PovfwCtx, err = NewUnixParserCtx(patternDir, cConfig.ConfigPaths.DataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load postovflw parser patterns: %w", err)
	}

	/*
		Load enrichers
	*/
	log.Info("Loading enrich plugins")

	parsers.EnricherCtx, err = Loadplugin()
	if err != nil {
		return nil, fmt.Errorf("failed to load enrich plugin: %w", err)
	}

	/*
	 Load the actual parsers
	*/

	log.Infof("Loading parsers from %d files", len(parsers.StageFiles))

	parsers.Nodes, err = LoadStages(parsers.StageFiles, parsers.Ctx, parsers.EnricherCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to load parser config: %w", err)
	}

	if len(parsers.PovfwStageFiles) > 0 {
		log.Info("Loading postoverflow parsers")

		parsers.Povfwnodes, err = LoadStages(parsers.PovfwStageFiles, parsers.PovfwCtx, parsers.EnricherCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to load postoverflow config: %w", err)
		}
	} else {
		log.Info("No postoverflow parsers to load")

		parsers.Povfwnodes = []Node{}
	}

	if cConfig.Prometheus != nil && cConfig.Prometheus.Enabled {
		parsers.Ctx.Profiling = true
		parsers.PovfwCtx.Profiling = true
	}
	/*
		Reset CTX grok to reduce memory footprint after we compile all the patterns
	*/
	parsers.Ctx.Grok = grokky.Host{}
	parsers.PovfwCtx.Grok = grokky.Host{}
	parsers.StageFiles = []Stagefile{}
	parsers.PovfwStageFiles = []Stagefile{}

	return parsers, nil
}
