package exprhelpers

import (
	"strconv"

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

func GetExprEnv(ctx map[string]interface{}) map[string]interface{} {

	var ExprLib = map[string]interface{}{"Atof": Atof}
	for k, v := range ctx {
		ExprLib[k] = v
	}
	return ExprLib
}
