package types

import "time"

type Line struct {
	Raw     string            `yaml:"Raw,omitempty"`
	Src     string            `yaml:"Src,omitempty"`
	Time    time.Time         //acquis time
	Labels  map[string]string `yaml:"Labels,omitempty"`
	Process bool
	Module  string `yaml:"Module,omitempty"`
}
