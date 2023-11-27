package waf

//This is a copy paste from expr_lib.go, we probably want to only have one ?

type exprCustomFunc struct {
	name      string
	function  func(params ...any) (any, error)
	signature []interface{}
}

/*
func GetOnLoadEnv(w *WaapRuntimeConfig) map[string]interface{} {
	return map[string]interface{}{
		"DisableInBandRuleByID":   w.DisableInBandRuleByID,
		"DisableOutBandRuleByID":  w.DisableOutBandRuleByID,
		"DisableInBandRuleByTag":  w.DisableInBandRuleByTag,
		"DisableOutBandRuleByTag": w.DisableOutBandRuleByTag,
	}
}
*/

/*var onLoadExprFuncs = []exprCustomFunc{
	{
		name:     "DisableInBandRuleByID",
		function: w.DisableInBandRuleByID,
		signature: []interface{}{
			new(func(int) error),
		},
	},
}*/

var preEvalExprFuncs = []exprCustomFunc{}

var onMatchExprFuncs = []exprCustomFunc{}

var exprFuncs = []exprCustomFunc{
	/*{
		name:     "SetRulesToInband",
		function: SetRulesToInband,
		signature: []interface{}{
			new(func() error),
		},
	},
	{
		name:     "SetRulesToOutOfBand",
		function: SetRulesToOutOfBand,
		signature: []interface{}{
			new(func() error),
		},
	},*/
}
