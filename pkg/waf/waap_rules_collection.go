package waf

import corazatypes "github.com/crowdsecurity/coraza/v3/types"

// to be filled w/ seb update
type WaapCollection struct {
}

// to be filled w/ seb update
type WaapCollectionConfig struct {
	SecLangFilesRules []string `yaml:"seclang_files_rules"`
	SecLangRules      []string `yaml:"seclang_rules"`
	MergedRules       []string `yaml:"-"`
}

func LoadCollection(collection string) (WaapCollection, error) {
	return WaapCollection{}, nil
}

func (wcc WaapCollectionConfig) LoadCollection(collection string) (WaapCollection, error) {
	return WaapCollection{}, nil
}

func (w WaapCollection) Check() error {
	return nil
}

func (w WaapCollection) Eval(req ParsedRequest) (*corazatypes.Interruption, error) {
	return nil, nil
}

func (w WaapCollection) GetDisplayName() string {
	return "rule XX"
}
