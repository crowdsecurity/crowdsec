//go:build no_mlsupport

package exprhelpers

import (
	"errors"
	"fmt"
)

var robertaInferencePipeline *RobertaInferencePipelineStub

type RobertaInferencePipelineStub struct{}

func InitRobertaInferencePipeline(modelBundlePath string) error {
	fmt.Println("Stub: InitRobertaInferencePipeline called with no ML support")
	return nil
}

func IsAnomalous(params ...any) (any, error) {
	_, ok1 := params[0].(string)
	_, ok2 := params[1].(string)

	if !ok1 || !ok2 {
		return nil, errors.New("parameters must be strings")
	}
	fmt.Println("IsAnomalous: InitRobertaInferencePipeline called with no ML support")

	return false, nil
}
