package parser

import (
	"testing"

	yaml "gopkg.in/yaml.v2"
)

func TestParserConfigs(t *testing.T) {
	pctx, err := NewUnixParserCtx("../../config/patterns/", "./testdata/")
	if err != nil {
		t.Fatalf("unable to load patterns : %s", err)
	}

	/*the actual tests*/
	var CfgTests = []struct {
		cfg      NodeConfig
		compiles bool
		valid    bool
	}{
		//valid node with grok pattern
		{NodeConfig{Debug: true, Stage: "s00", Grok: GrokPattern{RegexpValue: "^x%{DATA:extr}$", TargetField: "t"}}, true, true},
		//bad filter
		{NodeConfig{Debug: true, Stage: "s00", Filter: "ratata"}, false, false},
		//empty node
		{NodeConfig{Debug: true, Stage: "s00", Filter: "true"}, false, false},
		//bad subgrok
		{NodeConfig{Debug: true, Stage: "s00", SubGroks: yaml.MapSlice{{Key: string("FOOBAR"), Value: string("[a-$")}}}, false, true},
		//valid node with grok pattern
		{NodeConfig{Debug: true, Stage: "s00", SubGroks: yaml.MapSlice{{Key: string("FOOBAR"), Value: string("[a-z]")}}, Grok: GrokPattern{RegexpValue: "^x%{FOOBAR:extr}$", TargetField: "t"}}, true, true},
		//bad node success
		{NodeConfig{Debug: true, Stage: "s00", OnSuccess: "ratat", Grok: GrokPattern{RegexpValue: "^x%{DATA:extr}$", TargetField: "t"}}, false, false},
		//ok node success
		{NodeConfig{Debug: true, Stage: "s00", OnSuccess: "continue", Grok: GrokPattern{RegexpValue: "^x%{DATA:extr}$", TargetField: "t"}}, true, true},
		//valid node with grok sub-pattern used by name
		{NodeConfig{Debug: true, Stage: "s00", SubGroks: yaml.MapSlice{{Key: string("FOOBARx"), Value: string("[a-z] %{DATA:lol}$")}}, Grok: GrokPattern{RegexpName: "FOOBARx", TargetField: "t"}}, true, true},
		//node with unexisting grok pattern
		{NodeConfig{Debug: true, Stage: "s00", Grok: GrokPattern{RegexpName: "RATATA", TargetField: "t"}}, false, true},
		//node with grok pattern dependencies
		{NodeConfig{Debug: true, Stage: "s00", SubGroks: yaml.MapSlice{
			{Key: string("SUBGROK"), Value: string("[a-z]")},
			{Key: string("MYGROK"), Value: string("[a-z]%{SUBGROK}")},
		}, Grok: GrokPattern{RegexpValue: "^x%{MYGROK:extr}$", TargetField: "t"}}, true, true},
		//node with broken grok pattern dependencies
		{NodeConfig{Debug: true, Stage: "s00", SubGroks: yaml.MapSlice{
			{Key: string("SUBGROKBIS"), Value: string("[a-z]%{MYGROKBIS}")},
			{Key: string("MYGROKBIS"), Value: string("[a-z]")},
		}, Grok: GrokPattern{RegexpValue: "^x%{MYGROKBIS:extr}$", TargetField: "t"}}, false, true},
	}

	for idx, tc := range CfgTests {
		node := &Node{NodeConfig: tc.cfg}
		err := node.compile(pctx, EnricherCtx{})
		if tc.compiles && err != nil {
			t.Fatalf("Compile: (%d/%d) expected valid, got : %s", idx+1, len(CfgTests), err)
		}

		if !tc.compiles && err == nil {
			t.Fatalf("Compile: (%d/%d) expected error", idx+1, len(CfgTests))
		}

		err = node.validate(EnricherCtx{})
		if tc.valid && err != nil {
			t.Fatalf("Valid: (%d/%d) expected valid, got : %s", idx+1, len(CfgTests), err)
		}

		if !tc.valid && err == nil {
			t.Fatalf("Valid: (%d/%d) expected error", idx+1, len(CfgTests))
		}
	}
}
