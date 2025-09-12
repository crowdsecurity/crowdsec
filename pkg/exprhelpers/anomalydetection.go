//go:build !no_mlsupport

package exprhelpers

import (
	"errors"
	"fmt"
	"log"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion/component"
	"github.com/crowdsecurity/crowdsec/pkg/ml"
)

var robertaInferencePipeline *ml.RobertaClassificationInferencePipeline

//nolint:gochecknoinits
func init() {
	component.Register("mlsupport")
}

func InitRobertaInferencePipeline(modelBundlePath string) error {
	var err error

	fmt.Println("Initializing Roberta Inference Pipeline")

	robertaInferencePipeline, err = ml.NewRobertaInferencePipeline(modelBundlePath)
	if err != nil {
		return err
	}
	if robertaInferencePipeline == nil {
		fmt.Println("Failed to initialize Roberta Inference Pipeline")
	}

	return nil
}

func IsAnomalous(params ...any) (any, error) {
	verb, ok1 := params[0].(string)
	httpPath, ok2 := params[1].(string)

	if !ok1 || !ok2 {
		return nil, errors.New("parameters must be strings")
	}

	text := verb + " " + httpPath
	log.Println("Verb : ", verb)
	log.Println("HTTP Path : ", httpPath)
	log.Println("Text to analyze for Anomaly: ", text)

	if robertaInferencePipeline == nil {
		return nil, errors.New("Roberta Inference Pipeline not properly initialized")
	}

	result, err := robertaInferencePipeline.PredictLabel(text)
	boolean_label := result == 1
	return boolean_label, err
}
