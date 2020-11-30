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
		log.Errorf("jsonExtractLib : %+v : %s", target, err)
		return ""
	}
	if dataType == jsonparser.NotExist {
		log.Debugf("%+v doesn't exist", target)
		return ""
	}
	strvalue := string(value)
	//debug stuff
	return strvalue
}

func JsonExtract(jsblob string, target string) string {
	if !strings.HasPrefix(target, "[") {
		target = strings.Replace(target, "[", ".[", -1)
	}
	fullpath := strings.Split(target, ".")

	log.Tracef("extract path %+v", fullpath)
	return JsonExtractLib(jsblob, fullpath...)
}
