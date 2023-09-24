package exprhelpers

import (
	"errors"
	"fmt"
	"strings"

	"github.com/buger/jsonparser"
	json "github.com/goccy/go-json"
	log "github.com/sirupsen/logrus"
)

// func JsonExtractLib(jsblob string, target ...string) string {
func JsonExtractLib(params ...any) (any, error) {
	jsblob := params[0].(string)
	target := params[1].([]string)
	value, dataType, _, err := jsonparser.Get(
		jsonparser.StringToBytes(jsblob),
		target...,
	)

	if err != nil {
		if errors.Is(err, jsonparser.KeyPathNotFoundError) {
			log.Debugf("%+v doesn't exist", target)
			return "", nil
		}
		log.Errorf("jsonExtractLib : %+v : %s", target, err)
		return "", nil
	}
	if dataType == jsonparser.NotExist {
		log.Debugf("%+v doesn't exist", target)
		return "", nil
	}
	strvalue := string(value)
	return strvalue, nil
}

// func JsonExtractUnescape(jsblob string, target ...string) string {
func JsonExtractUnescape(params ...any) (any, error) {
	var value string
	var err error
	jsblob := params[0].(string)
	switch v := params[1].(type) {
	case string:
		target := v
		value, err = jsonparser.GetString(
			jsonparser.StringToBytes(jsblob),
			target,
		)
	case []string:
		target := v
		value, err = jsonparser.GetString(
			jsonparser.StringToBytes(jsblob),
			target...,
		)
	}

	if err != nil {
		if errors.Is(err, jsonparser.KeyPathNotFoundError) {
			log.Debugf("%+v doesn't exist", params[1])
			return "", nil
		}
		log.Errorf("JsonExtractUnescape : %+v : %s", params[1], err)
		return "", nil
	}
	log.Tracef("extract path %+v", params[1])
	return value, nil
}

// func JsonExtract(jsblob string, target string) string {
func JsonExtract(params ...any) (any, error) {
	jsblob := params[0].(string)
	target := params[1].(string)
	if !strings.HasPrefix(target, "[") {
		target = strings.ReplaceAll(target, "[", ".[")
	}
	fullpath := strings.Split(target, ".")

	log.Tracef("extract path %+v", fullpath)
	return JsonExtractLib(jsblob, fullpath)
}

func jsonExtractType(jsblob string, target string, t jsonparser.ValueType) ([]byte, error) {
	if !strings.HasPrefix(target, "[") {
		target = strings.ReplaceAll(target, "[", ".[")
	}
	fullpath := strings.Split(target, ".")

	log.Tracef("extract path %+v", fullpath)

	value, dataType, _, err := jsonparser.Get(
		jsonparser.StringToBytes(jsblob),
		fullpath...,
	)

	if err != nil {
		if errors.Is(err, jsonparser.KeyPathNotFoundError) {
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

// func JsonExtractSlice(jsblob string, target string) []interface{} {
func JsonExtractSlice(params ...any) (any, error) {
	jsblob := params[0].(string)
	target := params[1].(string)
	value, err := jsonExtractType(jsblob, target, jsonparser.Array)

	if err != nil {
		log.Errorf("JsonExtractSlice : %s", err)
		return []interface{}(nil), nil
	}

	s := make([]interface{}, 0)

	err = json.Unmarshal(value, &s)
	if err != nil {
		log.Errorf("JsonExtractSlice: could not convert '%s' to slice: %s", value, err)
		return []interface{}(nil), nil
	}
	return s, nil
}

// func JsonExtractObject(jsblob string, target string) map[string]interface{} {
func JsonExtractObject(params ...any) (any, error) {
	jsblob := params[0].(string)
	target := params[1].(string)
	value, err := jsonExtractType(jsblob, target, jsonparser.Object)

	if err != nil {
		log.Errorf("JsonExtractObject: %s", err)
		return map[string]interface{}(nil), nil
	}

	s := make(map[string]interface{})

	err = json.Unmarshal(value, &s)
	if err != nil {
		log.Errorf("JsonExtractObject: could not convert '%s' to map[string]interface{}: %s", value, err)
		return map[string]interface{}(nil), nil
	}
	return s, nil
}

// func ToJson(obj interface{}) string {
func ToJson(params ...any) (any, error) {
	obj := params[0]
	b, err := json.Marshal(obj)
	if err != nil {
		log.Errorf("ToJson : %s", err)
		return "", nil
	}
	return string(b), nil
}

// Func UnmarshalJSON(jsonBlob []byte, target interface{}) error {
func UnmarshalJSON(params ...any) (any, error) {
	jsonBlob := params[0].(string)
	target := params[1].(map[string]interface{})
	key := params[2].(string)

	var out interface{}

	err := json.Unmarshal([]byte(jsonBlob), &out)
	if err != nil {
		log.WithField("line", jsonBlob).Errorf("UnmarshalJSON : %s", err)
		return nil, err
	}
	target[key] = out
	return nil, nil
}
