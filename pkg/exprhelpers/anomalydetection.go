package exprhelpers

import (
	"errors"
	"fmt"
	"log"

	"github.com/crowdsecurity/crowdsec/pkg/ml"
)

var robertaInferencePipeline *ml.RobertaClassificationInferencePipeline

func InitRobertaInferencePipeline(datadir string) error {
	var err error

	fmt.Println("Initializing Roberta Inference Pipeline")

	robertaInferencePipeline, err = ml.NewRobertaInferencePipeline(datadir)
	if err != nil {
		return err
	}

	return nil
}

func AnomalyDetection(params ...any) (any, error) {
	verb, ok1 := params[0].(string)
	httpPath, ok2 := params[1].(string)

	if !ok1 || !ok2 {
		return nil, errors.New("parameters must be strings")
	}

	text := verb + " " + httpPath
	log.Println("Verb : ", verb)
	log.Println("HTTP Path : ", httpPath)
	log.Println("Text to analyze for Anomaly: ", text)

	result, err := robertaInferencePipeline.PredictLabel(text)
	boolean_label := result == 1
	return boolean_label, err
}
