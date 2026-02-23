package parser

import (
	yaml "gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/enrichment"
)

// NodeConfig is the YAML shape of a parser node.
type NodeConfig struct {
	FormatVersion string `yaml:"format"`
	// Enable config + runtime debug of node via config o/
	Debug bool `yaml:"debug,omitempty"`
	// If enabled, the node (and its child) will report their own statistics
	Profiling bool `yaml:"profiling,omitempty"`
	// Name, author, description and reference(s) for parser pattern
	Name        string   `yaml:"name,omitempty"`
	Author      string   `yaml:"author,omitempty"`
	Description string   `yaml:"description,omitempty"`
	References  []string `yaml:"references,omitempty"`
	// This is mostly a hack to make writing less repetitive.
	// relying on stage, we know which field to parse, and we
	// can also promote log to next stage on success
	Stage string `yaml:"stage,omitempty"`
	// OnSuccess allows to tag a node to be able to move log to next stage on success
	OnSuccess string `yaml:"onsuccess,omitempty"`
	Filter    string `yaml:"filter,omitempty"`
	/* If the node is actually a leaf, it can have : grok, enrich, statics */
	// pattern_syntax are named grok patterns that are re-utilized over several grok patterns
	SubGroks yaml.MapSlice `yaml:"pattern_syntax,omitempty"`

	// Holds a grok pattern
	Grok GrokPattern `yaml:"grok,omitempty"`
	// Statics can be present in any type of node and is executed last
	Statics []Static `yaml:"statics,omitempty"`
	// Stash allows to capture data from the log line and store it in an accessible cache
	Stashes   []Stash                    `yaml:"stash,omitempty"`
	Whitelist Whitelist                  `yaml:"whitelist,omitempty"`
	Data      []*enrichment.DataProvider `yaml:"data,omitempty"`
}
