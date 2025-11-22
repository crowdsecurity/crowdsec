//go:build !no_mlsupport
package ml

import (
	"fmt"

	onnxruntime "github.com/crowdsecurity/go-onnxruntime"
)

type OrtSession struct {
	ORTSession        *onnxruntime.ORTSession
	ORTEnv            *onnxruntime.ORTEnv
	ORTSessionOptions *onnxruntime.ORTSessionOptions
}

func NewOrtSession(modelPath string) (*OrtSession, error) {
	ortEnv := onnxruntime.NewORTEnv(onnxruntime.ORT_LOGGING_LEVEL_ERROR, "development")
	if ortEnv == nil {
		return nil, fmt.Errorf("failed to create ORT environment")
	}

	ortSessionOptions := onnxruntime.NewORTSessionOptions()
	if ortSessionOptions == nil {
		ortEnv.Close()
		return nil, fmt.Errorf("failed to create ORT session options")
	}

	fmt.Println("Creating ORT session from model path:", modelPath)

	session, err := onnxruntime.NewORTSession(ortEnv, modelPath, ortSessionOptions)
	if err != nil {
		fmt.Println("Error creating ORT session")
		ortEnv.Close()
		ortSessionOptions.Close()
		return nil, err
	}

	fmt.Println("Done creating ORT session")

	return &OrtSession{
		ORTSession:        session,
		ORTEnv:            ortEnv,
		ORTSessionOptions: ortSessionOptions,
	}, nil
}

func (ort *OrtSession) Predict(inputs []onnxruntime.TensorValue) ([]onnxruntime.TensorValue, error) {
	res, err := ort.ORTSession.Predict(inputs)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (ort *OrtSession) PredictLabel(inputIds []onnxruntime.TensorValue) (int, error) {
	res, err := ort.Predict(inputIds)
	if err != nil {
		return 0, err
	}

	label, err := PredicitonToLabel(res)
	if err != nil {
		return 0, err
	}

	return label, nil
}

func GetTensorValue(input []int64, shape []int64) onnxruntime.TensorValue {
	return onnxruntime.TensorValue{
		Shape: shape,
		Value: input,
	}
}

func PredicitonToLabel(res []onnxruntime.TensorValue) (int, error) {
	if len(res) != 1 {
		return 0, fmt.Errorf("expected one output tensor, got %d", len(res))
	}

	outputTensor := res[0]

	maxIndex := 0                                // Assuming the output tensor shape is [1 2], and we want to find the index of the max value
	maxProb := outputTensor.Value.([]float32)[0] // Assuming the values are float32

	for i, value := range outputTensor.Value.([]float32) {
		if value > maxProb {
			maxProb = value
			maxIndex = i
		}
	}

	return maxIndex, nil
}

func (os *OrtSession) Close() {
	os.ORTSession.Close()
	os.ORTEnv.Close()
	os.ORTSessionOptions.Close()
}
