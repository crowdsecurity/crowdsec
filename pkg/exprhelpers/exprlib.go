package exprhelpers

import (
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

func Atof(x string) float64 {
	log.Debugf("debug atof %s", x)
	ret, err := strconv.ParseFloat(x, 64)
	if err != nil {
		log.Warningf("Atof : can't convert float '%s' : %v", x, err)
	}
	return ret
}

func StartsWith(s string, pref string) bool {
	return strings.HasPrefix(s, pref)
}

func EndsWith(s string, suff string) bool {
	return strings.HasSuffix(s, suff)
}

func GetExprEnv(ctx map[string]interface{}) map[string]interface{} {

	var ExprLib = map[string]interface{}{"Atof": Atof, "JsonExtract": JsonExtract, "JsonExtractLib": JsonExtractLib}
	for k, v := range ctx {
		ExprLib[k] = v
	}
	return ExprLib
}
