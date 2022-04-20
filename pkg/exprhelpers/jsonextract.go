package exprhelpers

import (
	"encoding/json"
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
		if err == jsonparser.KeyPathNotFoundError {
			log.Debugf("%+v doesn't exist", target)
			return ""
		}
		log.Errorf("jsonExtractLib : %+v : %s", target, err)
		return ""
	}
	if dataType == jsonparser.NotExist {
		log.Debugf("%+v doesn't exist", target)
		return ""
	}
	strvalue := string(value)
	return strvalue
}

func JsonExtractUnescape(jsblob string, target ...string) string {
	value, err := jsonparser.GetString(
		jsonparser.StringToBytes(jsblob),
		target...,
	)

	if err != nil {
		if err == jsonparser.KeyPathNotFoundError {
			log.Debugf("%+v doesn't exist", target)
			return ""
		}
		log.Errorf("JsonExtractUnescape : %+v : %s", target, err)
		return ""
	}
	log.Tracef("extract path %+v", target)
	strvalue := string(value)
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

func JsonExtractSlice(jsblob string, target string) []interface{} {
	if !strings.HasPrefix(target, "[") {
		target = strings.Replace(target, "[", ".[", -1)
	}
	fullpath := strings.Split(target, ".")

	log.Tracef("extract path %+v", fullpath)
	bContent := JsonExtractLib(jsblob, fullpath...)
	ret := make([]interface{}, 0)
	json.Unmarshal([]byte(bContent), &ret)
	return ret
}

/*func JsonExtractMap(jsblob string, target string) map[string]interface{} {
	if !strings.HasPrefix(target, "[") {
		target = strings.Replace(target, "[", ".[", -1)
	}
	fullpath := strings.Split(target, ".")

	log.Tracef("extract path %+v", fullpath)
	bContent := JsonExtractLib(jsblob, fullpath...)
	ret := make(map[string]interface{}, 0)
	json.Unmarshal([]byte(bContent), &ret)
	return ret
}*/
