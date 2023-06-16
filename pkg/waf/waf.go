package waf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type Hook struct {
	Filter     string        `yaml:"filter"`
	FilterExpr *vm.Program   `yaml:"-"`
	OnSuccess  string        `yaml:"on_success"`
	Apply      []string      `yaml:"apply"`
	ApplyExpr  []*vm.Program `yaml:"-"`
}

type CompiledHook struct {
	Filter *vm.Program   `yaml:"-"`
	Apply  []*vm.Program `yaml:"-"`
}

/*type WafConfig struct {
	InbandRules    []WafRule
	OutOfBandRules []WafRule
	Datadir        string
	logger         *log.Entry
}*/

// This represents one "waf-rule" config
type WafConfig struct {
	SecLangFilesRules []string `yaml:"seclang_files_rules"`
	SecLangRules      []string `yaml:"seclang_rules"`
	OnLoad            []Hook   `yaml:"on_load"`
	PreEval           []Hook   `yaml:"pre_eval"`
	OnMatch           []Hook   `yaml:"on_match"`

	CompiledOnLoad  []CompiledHook `yaml:"-"`
	CompiledPreEval []CompiledHook `yaml:"-"`
	CompiledOnMatch []CompiledHook `yaml:"-"`

	MergedRules []string `yaml:"-"`
	OutOfBand   bool     `yaml:"outofband"`
}

type WafRuleLoader struct {
	logger  *log.Entry
	Datadir string
}

func buildHook(hook Hook) (CompiledHook, error) {
	compiledHook := CompiledHook{}
	if hook.Filter != "" {
		program, err := expr.Compile(hook.Filter) //FIXME: opts
		if err != nil {
			return CompiledHook{}, fmt.Errorf("unable to compile filter %s : %w", hook.Filter, err)
		}
		compiledHook.Filter = program
	}
	for _, apply := range hook.Apply {
		program, err := expr.Compile(apply, GetExprWAFOptions(map[string]interface{}{
			"rules": &WafRulesCollection{},
		})...)
		if err != nil {
			return CompiledHook{}, fmt.Errorf("unable to compile apply %s : %w", apply, err)
		}
		compiledHook.Apply = append(compiledHook.Apply, program)
	}
	return compiledHook, nil
}

func (w *WafRuleLoader) LoadWafRules() ([]*WafRulesCollection, error) {
	var wafRulesFiles []string
	for _, hubWafRuleItem := range cwhub.GetItemMap(cwhub.WAF_RULES) {
		if hubWafRuleItem.Installed {
			wafRulesFiles = append(wafRulesFiles, hubWafRuleItem.LocalPath)
		}
	}

	if len(wafRulesFiles) == 0 {
		return nil, fmt.Errorf("no waf rules found in hub")
	}

	w.logger.Infof("Loading %d waf files", len(wafRulesFiles))
	wafRulesCollections := []*WafRulesCollection{}
	for _, wafRulesFile := range wafRulesFiles {

		fileContent, err := os.ReadFile(wafRulesFile)
		if err != nil {
			w.logger.Errorf("unable to read file %s : %s", wafRulesFile, err)
			continue
		}
		wafConfig := WafConfig{}
		err = yaml.Unmarshal(fileContent, &wafConfig)
		if err != nil {
			w.logger.Errorf("unable to unmarshal file %s : %s", wafRulesFile, err)
			continue
		}

		spew.Dump(wafConfig)

		collection := &WafRulesCollection{}

		if wafConfig.SecLangFilesRules != nil {
			for _, rulesFile := range wafConfig.SecLangFilesRules {
				fullPath := filepath.Join(w.Datadir, rulesFile)
				c, err := os.ReadFile(fullPath)
				if err != nil {
					w.logger.Errorf("unable to read file %s : %s", rulesFile, err)
					continue
				}
				for _, line := range strings.Split(string(c), "\n") {
					if strings.HasPrefix(line, "#") {
						continue
					}
					if strings.TrimSpace(line) == "" {
						continue
					}
					collection.Rules = append(collection.Rules, WafRule{RawRule: line})
				}
			}
		}

		if wafConfig.SecLangRules != nil {
			for _, rule := range wafConfig.SecLangRules {
				collection.Rules = append(collection.Rules, WafRule{RawRule: rule})
			}
		}

		//TODO: add our own format

		//compile hooks
		for _, hook := range wafConfig.OnLoad {
			compiledHook, err := buildHook(hook)
			if err != nil {
				w.logger.Errorf("unable to build on_load hook %s : %s", hook.Filter, err)
				continue
			}
			collection.CompiledOnLoad = append(collection.CompiledOnLoad, compiledHook)
		}

		for _, hook := range wafConfig.PreEval {
			compiledHook, err := buildHook(hook)
			if err != nil {
				w.logger.Errorf("unable to build pre_eval hook %s : %s", hook.Filter, err)
				continue
			}
			collection.CompiledPreEval = append(collection.CompiledPreEval, compiledHook)
		}

		for _, hook := range wafConfig.OnMatch {
			compiledHook, err := buildHook(hook)
			if err != nil {
				w.logger.Errorf("unable to build on_match hook %s : %s", hook.Filter, err)
				continue
			}
			collection.CompiledOnMatch = append(collection.CompiledOnMatch, compiledHook)
		}

		//Run the on_load hooks
		if len(collection.CompiledOnLoad) > 0 {
			w.logger.Infof("Running %d on_load hooks", len(collection.CompiledOnLoad))
			for hookIdx, onLoadHook := range collection.CompiledOnLoad {
				//Ignore filter for on load ?
				if onLoadHook.Apply != nil {
					for exprIdx, applyExpr := range onLoadHook.Apply {
						_, err := expr.Run(applyExpr, map[string]interface{}{
							"rules": collection,
						})
						if err != nil {
							w.logger.Errorf("unable to run apply for on_load rule %s : %s", wafConfig.OnLoad[hookIdx].Apply[exprIdx], err)
							continue
						}
					}
				}
			}
		}
		wafRulesCollections = append(wafRulesCollections, collection)
	}

	return wafRulesCollections, nil
}

func NewWafRuleLoader() *WafRuleLoader {
	//FIXME: find a better way to get the datadir
	clog := log.New()
	if err := types.ConfigureLogger(clog); err != nil {
		//return nil, fmt.Errorf("while configuring datasource logger: %w", err)
		return nil
	}
	logger := clog.WithFields(log.Fields{
		"type": "waf-config",
	})

	initWafHelpers()

	return &WafRuleLoader{Datadir: csconfig.DataDir, logger: logger}
}
