package parser

import (
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func TestParserConfigs(t *testing.T) {
	pctx, err := Init(map[string]interface{}{"patterns": "../../config/patterns/", "data": "./tests/"})
	if err != nil {
		t.Fatalf("unable to load patterns : %s", err)
	}

	/*the actual tests*/
	var CfgTests = []struct {
		NodeCfg  *Node
		Compiles bool
		Valid    bool
	}{
		//valid node with grok pattern
		{&Node{Debug: true, Stage: "s00", Grok: types.GrokPattern{RegexpValue: "^x%{DATA:extr}$", TargetField: "t"}}, true, true},
		//bad filter
		{&Node{Debug: true, Stage: "s00", Filter: "ratata"}, false, false},
		//empty node
		{&Node{Debug: true, Stage: "s00", Filter: "true"}, false, false},
		//bad subgrok
		{&Node{Debug: true, Stage: "s00", SubGroks: map[string]string{"FOOBAR": "[a-$"}}, false, true},
		//valid node with grok pattern
		{&Node{Debug: true, Stage: "s00", SubGroks: map[string]string{"FOOBAR": "[a-z]"}, Grok: types.GrokPattern{RegexpValue: "^x%{FOOBAR:extr}$", TargetField: "t"}}, true, true},
		//bad node success
		{&Node{Debug: true, Stage: "s00", OnSuccess: "ratat", Grok: types.GrokPattern{RegexpValue: "^x%{DATA:extr}$", TargetField: "t"}}, false, false},
		//ok node success
		{&Node{Debug: true, Stage: "s00", OnSuccess: "continue", Grok: types.GrokPattern{RegexpValue: "^x%{DATA:extr}$", TargetField: "t"}}, true, true},
		//valid node with grok sub-pattern used by name
		{&Node{Debug: true, Stage: "s00", SubGroks: map[string]string{"FOOBARx": "[a-z] %{DATA:lol}$"}, Grok: types.GrokPattern{RegexpName: "FOOBARx", TargetField: "t"}}, true, true},
		//node with unexisting grok pattern
		{&Node{Debug: true, Stage: "s00", Grok: types.GrokPattern{RegexpName: "RATATA", TargetField: "t"}}, false, true},

		//bad grok pattern
		//{&Node{Debug: true, Grok: []GrokPattern{ GrokPattern{}, }}, false},
	}
	for idx := range CfgTests {
		err := CfgTests[idx].NodeCfg.compile(pctx)
		if CfgTests[idx].Compiles == true && err != nil {
			t.Fatalf("Compile: (%d/%d) expected valid, got : %s", idx+1, len(CfgTests), err)
		}
		if CfgTests[idx].Compiles == false && err == nil {
			t.Fatalf("Compile: (%d/%d) expected errror", idx+1, len(CfgTests))
		}

		err = CfgTests[idx].NodeCfg.validate(pctx)
		if CfgTests[idx].Valid == true && err != nil {
			t.Fatalf("Valid: (%d/%d) expected valid, got : %s", idx+1, len(CfgTests), err)
		}
		if CfgTests[idx].Valid == false && err == nil {
			t.Fatalf("Valid: (%d/%d) expected error", idx+1, len(CfgTests))
		}

	}
}
