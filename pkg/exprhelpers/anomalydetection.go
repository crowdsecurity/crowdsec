package exprhelpers

import (
	"errors"
	"log"

	"github.com/crowdsecurity/crowdsec/pkg/ml"
)

func AnomalyDetection(params ...any) (any, error) {
	verb, ok1 := params[0].(string)
	http_path, ok2 := params[1].(string)

	if !ok1 || !ok2 {
		return nil, errors.New("parameters must be strings")
	}

	if len(verb) == 0 || len(http_path) == 0 {
		return 0, nil
	}

	text := verb + " " + http_path

	tk, err := ml.NewBBPETokenizer("tests")
	if err != nil {
		return nil, err
	}
	defer tk.Close()

	ids, _ := tk.Encode(text, false)

	shape := []int64{1, 256}
	input, err := ml.PrepareInput(ids, shape)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	modelPath := "tests/roberta-torch-export.onnx"
	res, err := ml.OnnxPrediction(modelPath, input, shape)
	if err != nil {
		log.Println(err)
		return 0, err
	}

	label, err := ml.PredicitonToLabel(res)
	if err != nil {
		log.Println(err)
		return 0, err
	}

	return label, nil
}
