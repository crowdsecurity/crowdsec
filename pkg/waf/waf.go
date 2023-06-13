package waf

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/types"
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

type WafRule struct {
	SecLangFilesRules []string `yaml:"seclang_files_rules"`
	SecLangRules      []string `yaml:"seclang_rules"`
	OnLoad            []Hook   `yaml:"on_load"`
	PreEval           []Hook   `yaml:"pre_eval"`
	OnMatch           []Hook   `yaml:"on_match"`

	CompiledOnLoad  []CompiledHook `yaml:"-"`
	CompiledPreEval []CompiledHook `yaml:"-"`
	CompiledOnMatch []CompiledHook `yaml:"-"`

	MergedRules []string `yaml:"-"`
	OutOfBand   bool     `yaml:"-"`
}

type WafConfig struct {
	InbandRules    []WafRule
	OutOfBandRules []WafRule
	Datadir        string
	logger         *log.Entry
}

func buildHook(hook Hook) (CompiledHook, error) {
	compiledHook := CompiledHook{}
	if hook.Filter != "" {
		program, err := expr.Compile(hook.Filter) //FIXME: opts
		if err != nil {
			log.Errorf("unable to compile filter %s : %s", hook.Filter, err)
			return CompiledHook{}, err
		}
		compiledHook.Filter = program
	}
	for _, apply := range hook.Apply {
		program, err := expr.Compile(apply, GetExprWAFOptions(map[string]interface{}{
			"InBandRules":    []WafRule{},
			"OutOfBandRules": []WafRule{},
		})...)
		if err != nil {
			log.Errorf("unable to compile apply %s : %s", apply, err)
			return CompiledHook{}, err
		}
		compiledHook.Apply = append(compiledHook.Apply, program)
	}
	return compiledHook, nil
}

func (w *WafConfig) LoadWafRules() error {
	var files []string
	for _, hubWafRuleItem := range cwhub.GetItemMap(cwhub.WAF_RULES) {
		if hubWafRuleItem.Installed {
			files = append(files, hubWafRuleItem.LocalPath)
		}
	}
	w.logger.Infof("Loading %d waf files", len(files))
	for _, file := range files {

		fileContent, err := os.ReadFile(file) //FIXME: actually read from datadir
		if err != nil {
			w.logger.Errorf("unable to read file %s : %s", file, err)
			continue
		}
		wafRule := WafRule{}
		err = yaml.Unmarshal(fileContent, &wafRule)
		if err != nil {
			w.logger.Errorf("unable to unmarshal file %s : %s", file, err)
			continue
		}
		if wafRule.SecLangFilesRules != nil {
			for _, rulesFile := range wafRule.SecLangFilesRules {
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
					wafRule.MergedRules = append(wafRule.MergedRules, line)
				}
			}
		}
		if wafRule.SecLangRules != nil {
			wafRule.MergedRules = append(wafRule.MergedRules, wafRule.SecLangRules...)
		}

		//compile hooks
		for _, hook := range wafRule.OnLoad {
			compiledHook, err := buildHook(hook)
			if err != nil {
				w.logger.Errorf("unable to build hook %s : %s", hook.Filter, err)
				continue
			}
			wafRule.CompiledOnLoad = append(wafRule.CompiledOnLoad, compiledHook)
		}

		for _, hook := range wafRule.PreEval {
			compiledHook, err := buildHook(hook)
			if err != nil {
				w.logger.Errorf("unable to build hook %s : %s", hook.Filter, err)
				continue
			}
			wafRule.CompiledPreEval = append(wafRule.CompiledPreEval, compiledHook)
		}

		for _, hook := range wafRule.OnMatch {
			compiledHook, err := buildHook(hook)
			if err != nil {
				w.logger.Errorf("unable to build hook %s : %s", hook.Filter, err)
				continue
			}
			wafRule.CompiledOnMatch = append(wafRule.CompiledOnMatch, compiledHook)
		}

		//Run the on_load hooks

		if len(wafRule.CompiledOnLoad) > 0 {
			w.logger.Infof("Running %d on_load hooks", len(wafRule.CompiledOnLoad))
			for hookIdx, onLoadHook := range wafRule.CompiledOnLoad {
				//Ignore filter for on load ?
				if onLoadHook.Apply != nil {
					for exprIdx, applyExpr := range onLoadHook.Apply {
						_, err := expr.Run(applyExpr, map[string]interface{}{
							"InBandRules":    []WafRule{},
							"OutOfBandRules": []WafRule{},
						})
						if err != nil {
							w.logger.Errorf("unable to run apply for on_load rule %s : %s", wafRule.OnLoad[hookIdx].Apply[exprIdx], err)
							continue
						}
					}
				}
			}
		}

		if wafRule.MergedRules != nil {
			if wafRule.OutOfBand {
				w.OutOfBandRules = append(w.OutOfBandRules, wafRule)
			} else {
				w.InbandRules = append(w.InbandRules, wafRule)
			}
		} else {
			w.logger.Warnf("no rules found in file %s ??", file)
		}
	}
	return nil
}

func NewWafConfig() *WafConfig {
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

	return &WafConfig{Datadir: csconfig.DataDir, logger: logger}
}

func (w *WafRule) String() string {
	return strings.Join(w.MergedRules, "\n")
}
