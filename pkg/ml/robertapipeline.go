package ml

import (
	"fmt"
	"log"
	"path/filepath"

	onnxruntime "github.com/crowdsecurity/go-onnxruntime"
)

type RobertaClassificationInferencePipeline struct {
	inputShape []int64
	tokenizer  *Tokenizer
	ortSession *OrtSession
}

func NewRobertaInferencePipeline(datadir string) (*RobertaClassificationInferencePipeline, error) {
	var err error

	fmt.Println("Initializing Roberta Inference Pipeline")

	// ortSession, err := NewOrtSession(filepath.Join(datadir, "roberta-torch-export.onnx"))
	ortSession, err := NewOrtSession(filepath.Join(datadir, "model.onnx"))
	if err != nil {
		return nil, err
	}

	tokenizer, err := NewTokenizer(datadir)
	if err != nil {
		return nil, err
	}

	inputShape := []int64{1, int64(tokenizer.modelMaxLength)}

	return &RobertaClassificationInferencePipeline{
		inputShape: inputShape,
		tokenizer:  tokenizer,
		ortSession: ortSession,
	}, nil
}

func (r *RobertaClassificationInferencePipeline) Close() {
	r.tokenizer.Close()
	r.ortSession.Close()
}

func (pipeline *RobertaClassificationInferencePipeline) PredictLabel(text string) (int, error) {
	ids, _, attentionMask, err := pipeline.tokenizer.Encode(text, false, true, true)
	// fmt.Println("RobertaClassificationInferencePipeline: ids: ", ids)
	// fmt.Println("RobertaClassificationInferencePipeline: attentionMask: ", attentionMask)
	if err != nil {
		fmt.Println(err)
		fmt.Println("Error encoding text")
		return 0, err
	}

	// fmt.Println("Running ONNX prediction")

	label, err := pipeline.ortSession.PredictLabel([]onnxruntime.TensorValue{
		GetTensorValue(ids, pipeline.inputShape),
		GetTensorValue(attentionMask, pipeline.inputShape),
	})
	if err != nil {
		fmt.Println(err)
		return 0, err
	}

	return label, nil
}

func HelloWorld() {
	text := "POST /"
	// text := "GET /kajakzeug/wattpaddler/favicon.ico"
	// text := "POST / <rp onmouseup=\"prompt(1)\">test</rp>"
	// text := "POST /cgi-bin/luci"

	fmt.Println("Text to analyze for Anomaly: ", text)

	pipeline, err := NewRobertaInferencePipeline("/Users/davidlequin/models")
	if err != nil {
		log.Fatalf("Failed to initialize pipeline: %v", err)
	}
	defer pipeline.Close()

	label, _ := pipeline.PredictLabel(text)

	log.Println("Anomaly detection result:", label == 1)
}
