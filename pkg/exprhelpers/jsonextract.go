package exprhelpers

import (
	"encoding/json"
	"fmt"
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

func jsonExtractType(jsblob string, target string, t jsonparser.ValueType) ([]byte, error) {
	if !strings.HasPrefix(target, "[") {
		target = strings.Replace(target, "[", ".[", -1)
	}
	fullpath := strings.Split(target, ".")

	log.Tracef("extract path %+v", fullpath)

	value, dataType, _, err := jsonparser.Get(
		jsonparser.StringToBytes(jsblob),
		fullpath...,
	)

	if err != nil {
		if err == jsonparser.KeyPathNotFoundError {
			log.Debugf("Key %+v doesn't exist", target)
			return nil, fmt.Errorf("key %s does not exist", target)
		}
		log.Errorf("jsonExtractType : %s : %s", target, err)
		return nil, fmt.Errorf("jsonExtractType: %s : %w", target, err)
	}

	if dataType != t {
		log.Errorf("jsonExtractType : expected type %s for target %s but found %s", t, target, dataType.String())
		return nil, fmt.Errorf("jsonExtractType: expected type %s for target %s but found %s", t, target, dataType.String())
	}

	return value, nil
}

func JsonExtractSlice(jsblob string, target string) []interface{} {

	value, err := jsonExtractType(jsblob, target, jsonparser.Array)

	if err != nil {
		log.Errorf("JsonExtractSlice : %s", err)
		return nil
	}

	s := make([]interface{}, 0)

	err = json.Unmarshal(value, &s)
	if err != nil {
		log.Errorf("JsonExtractSlice : %s : %s", target, err)
		return nil
	}
	return s
}

func JsonExtractObject(jsblob string, target string) map[string]interface{} {

	value, err := jsonExtractType(jsblob, target, jsonparser.Object)

	if err != nil {
		log.Errorf("JsonExtractObject: %s", err)
		return nil
	}

	s := make(map[string]interface{})

	err = json.Unmarshal(value, &s)
	if err != nil {
		log.Errorf("JsonExtractObject: %s : %s", target, err)
		return nil
	}
	return s
}

func ToJson(obj interface{}) string {
	b, err := json.Marshal(obj)
	if err != nil {
		log.Errorf("ToJson : %s", err)
		return ""
	}
	return string(b)
}
