package waf

//This is a copy paste from expr_lib.go, we probably want to only have one ?

type exprCustomFunc struct {
	name      string
	function  func(params ...any) (any, error)
	signature []interface{}
}

var exprFuncs = []exprCustomFunc{
	{
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
	},
}
