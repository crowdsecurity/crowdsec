package exprhelpers

import (
	"strings"

	"github.com/buger/jsonparser"

	log "github.com/sirupsen/logrus"
)

func JsonExtractLib(jsblob string, target ...string) string {
	value, dataType, _, err := jsonparser.Get(
		jsonparser.StringToBytes(jsblob),
		target...,
	)

	if err != nil {
		log.Errorf("jsonExtractLib : %s", err)
		return ""
	}
	if dataType == jsonparser.NotExist {
		log.Debugf("%+v doesn't exist", target)
		return ""
	}
	strvalue := string(value)
	return strvalue
}

func JsonExtract(jsblob string, target string) string {
	fullpath := strings.Split(target, ".")
	return JsonExtractLib(jsblob, fullpath...)
}
