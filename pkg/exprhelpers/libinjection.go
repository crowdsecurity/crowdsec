package exprhelpers

import "github.com/corazawaf/libinjection-go"

func LibInjectionIsSQLI(params ...any) (any, error) {
	str := params[0].(string)

	ret, _ := libinjection.IsSQLi(str)
	return ret, nil
}

func LibInjectionIsXSS(params ...any) (any, error) {
	str := params[0].(string)

	ret := libinjection.IsXSS(str)
	return ret, nil
}
