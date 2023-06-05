package waf

import (
	"os"
	"strings"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type Hook struct {
	Filter     string      `yaml:"filter"`
	FilterExpr *vm.Program `yaml:"-"`
	OnSuccess  string      `yaml:"on_success"`
	Apply      []string    `yaml:"apply"`
	ApplyExpr  []*vm.Program
}

type WafRule struct {
	SecLangFilesRules []string `yaml:"seclang_files_rules"`
	SecLangRules      []string `yaml:"seclang_rules"`
	OnLoad            []Hook   `yaml:"on_load"`
	PreEval           []Hook   `yaml:"pre_eval"`
	OnMatch           []Hook   `yaml:"on_match"`
	MergedRules       []string `yaml:"-"`
	OutOfBand         bool     `yaml:"-"`
}

type WafConfig struct {
	InbandRules    []WafRule
	OutOfBandRules []WafRule
}

func buildHook(hook Hook) (Hook, error) {
	if hook.Filter != "" {
		program, err := expr.Compile(hook.Filter) //FIXME: opts
		if err != nil {
			log.Errorf("unable to compile filter %s : %s", hook.Filter, err)
			return Hook{}, err
		}
		hook.FilterExpr = program
	}
	for _, apply := range hook.Apply {
		program, err := expr.Compile(apply) //FIXME: opts
		if err != nil {
			log.Errorf("unable to compile apply %s : %s", apply, err)
			return Hook{}, err
		}
		hook.ApplyExpr = append(hook.ApplyExpr, program)
	}
	return hook, nil
}

func (w *WafConfig) LoadWafRules() error {
	var files []string
	for _, hubWafRuleItem := range cwhub.GetItemMap(cwhub.WAF_RULES) {
		if hubWafRuleItem.Installed {
			files = append(files, hubWafRuleItem.LocalPath)
		}
	}
	log.Infof("Loading %d waf files", len(files))
	for _, file := range files {

		fileContent, err := os.ReadFile(file) //FIXME: actually read from datadir
		if err != nil {
			log.Errorf("unable to read file %s : %s", file, err)
			continue
		}
		wafRule := WafRule{}
		err = yaml.Unmarshal(fileContent, &wafRule)
		if err != nil {
			log.Errorf("unable to unmarshal file %s : %s", file, err)
			continue
		}
		if wafRule.SecLangFilesRules != nil {
			for _, rulesFile := range wafRule.SecLangFilesRules {
				c, err := os.ReadFile(rulesFile)
				if err != nil {
					log.Errorf("unable to read file %s : %s", rulesFile, err)
					continue
				}
				wafRule.MergedRules = append(wafRule.MergedRules, string(c))
			}
		}
		if wafRule.SecLangRules != nil {
			wafRule.MergedRules = append(wafRule.MergedRules, wafRule.SecLangRules...)
		}

		//compile hooks
		for _, hook := range wafRule.OnLoad {
			hook, err = buildHook(hook)
			if err != nil {
				log.Errorf("unable to build hook %s : %s", hook.Filter, err)
				continue
			}
		}

		for _, hook := range wafRule.PreEval {
			hook, err = buildHook(hook)
			if err != nil {
				log.Errorf("unable to build hook %s : %s", hook.Filter, err)
				continue
			}
		}

		for _, hook := range wafRule.OnMatch {
			hook, err = buildHook(hook)
			if err != nil {
				log.Errorf("unable to build hook %s : %s", hook.Filter, err)
				continue
			}
		}

		if wafRule.MergedRules != nil {
			if wafRule.OutOfBand {
				w.OutOfBandRules = append(w.OutOfBandRules, wafRule)
			} else {
				w.InbandRules = append(w.InbandRules, wafRule)
			}
		} else {
			log.Warnf("no rules found in file %s ??", file)
		}
	}
	return nil
}

func NewWafConfig() *WafConfig {
	return &WafConfig{}
}

func (w *WafRule) String() string {
	return strings.Join(w.MergedRules, "\n")
}
