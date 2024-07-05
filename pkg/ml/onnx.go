package ml

import (
	"fmt"
	"log"

	onnxruntime "github.com/ivansuteja96/go-onnxruntime"
)

func OnnxPrediction(modelPath string, input []int64, inputShape []int64) ([]onnxruntime.TensorValue, error) {
	ortEnv := onnxruntime.NewORTEnv(onnxruntime.ORT_LOGGING_LEVEL_ERROR, "development")
	defer ortEnv.Close()

	ortSessionOptions := onnxruntime.NewORTSessionOptions()
	defer ortSessionOptions.Close()

	model, err := onnxruntime.NewORTSession(ortEnv, modelPath, ortSessionOptions)
	if err != nil {
		return nil, err
	}
	defer model.Close()

	// Create tensor value
	inputTensor := onnxruntime.TensorValue{
		Value: input,
		Shape: inputShape,
	}

	// fmt.Printf("Input tensor: Value=%+v, Shape=%+v\n", inputTensor.Value, inputTensor.Shape)

	// Run the prediction
	res, err := model.Predict([]onnxruntime.TensorValue{inputTensor})
	if err != nil {
		return nil, err
	}
	// fmt.Printf("Output tensor: Shape=%+v, Value=%+v\n", res[0].Shape, res[0].Value)

	// fmt.Printf("Success do predict, shape: %+v, result: %+v\n", res[0].Shape, res[0].Value)

	return res, nil
}

func PrepareInput(tokenIDs []uint32, inputShape []int64) ([]int64, error) {
	sequenceLength := inputShape[1]
	input := make([]int64, sequenceLength)

	// Fill input tensor with tokenIds and pad with zeros
	for i := 0; i < len(tokenIDs) && i < int(sequenceLength); i++ {
		input[i] = int64(tokenIDs[i])
	}

	return input, nil
}

func PredicitonToLabel(res []onnxruntime.TensorValue) (int, error) {
	if len(res) != 1 {
		return 0, fmt.Errorf("expected one output tensor, got %d", len(res))
	}

	outputTensor := res[0]

	// Assuming the output tensor shape is [1 2], and we want to find the index of the max value
	maxIndex := 0
	maxProb := outputTensor.Value.([]float32)[0] // Assuming the values are float32

	for i, value := range outputTensor.Value.([]float32) {
		if value > maxProb {
			maxProb = value
			maxIndex = i
		}
	}

	return maxIndex, nil
}

func HelloWorld() {
	text := "hello world"

	tokenIds, tokens, err := tokenize(text)
	if err != nil {
		log.Println(err)
		return
	}

	fmt.Println("Token IDs:", tokenIds)
	fmt.Println("Tokens:", tokens)

	batchSize := int64(1)
	sequenceLength := int64(256)
	inputShape := []int64{batchSize, sequenceLength}

	input, err := PrepareInput(tokenIds, inputShape)
	if err != nil {
		log.Println(err)
		return
	}

	// fmt.Printf("Input: %+v\n", input)

	modelPath := "tests/roberta-torch-export.onnx"
	res, err := OnnxPrediction(modelPath, input, inputShape)
	if err != nil {
		log.Println(err)
		return
	}

	label, err := PredicitonToLabel(res)
	if err != nil {
		log.Println(err)
		return
	}

	fmt.Println("Label:", label)
}
