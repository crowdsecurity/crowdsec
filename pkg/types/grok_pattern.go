package types

import (
	"github.com/antonmedv/expr/vm"
	"github.com/crowdsecurity/grokky"
)

//Used mostly for statics
type ExtraField struct {
	//if the target is indicated by name Struct.Field etc,
	TargetByName string `yaml:"target,omitempty"`
	//if the target field is in Event map
	Parsed string `yaml:"parsed,omitempty"`
	//if the target field is in Meta map
	Meta string `yaml:"meta,omitempty"`
	//if the target field is in Enriched map
	Enriched string `yaml:"enriched,omitempty"`
	//the source is a static value
	Value string `yaml:"value,omitempty"`
	//or the result of an Expression
	ExpValue     string      `yaml:"expression,omitempty"`
	RunTimeValue *vm.Program `json:"-"` //the actual compiled filter
	//or an enrichment method
	Method string `yaml:"method,omitempty"`
}

type GrokPattern struct {
	//the field to which regexp is going to apply
	TargetField string `yaml:"apply_on,omitempty"`
	//the grok/regexp by name (loaded from patterns/*)
	RegexpName string `yaml:"name,omitempty"`
	//a proper grok pattern
	RegexpValue string `yaml:"pattern,omitempty"`
	//the runtime form of regexpname / regexpvalue
	RunTimeRegexp *grokky.Pattern `json:"-"` //the actual regexp
	//the output of the expression is going to be the source for regexp
	ExpValue     string      `yaml:"expression,omitempty"`
	RunTimeValue *vm.Program `json:"-"` //the actual compiled filter
	//a grok can contain statics that apply if pattern is successfull
	Statics []ExtraField `yaml:"statics,omitempty"`
}
