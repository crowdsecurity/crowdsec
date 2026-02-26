//go:build !no_ml_support

package ml

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	onnxruntime "github.com/crowdsecurity/go-onnxruntime"
)

type RobertaClassificationInferencePipeline struct {
	inputShape []int64
	tokenizer  *Tokenizer
	ortSession *OrtSession
}

var bundleFileList = []string{
	"model.onnx",
	"tokenizer.json",
	"tokenizer_config.json",
}

func NewRobertaInferencePipeline(bundleFilePath string) (*RobertaClassificationInferencePipeline, error) {
	tempDir, err := os.MkdirTemp("", "crowdsec_roberta_model_assets")
	if err != nil {
		return nil, fmt.Errorf("could not create temp directory: %v", err)
	}

	if err := extractTarFile(bundleFilePath, tempDir); err != nil {
		os.RemoveAll(tempDir)
		return nil, fmt.Errorf("failed to extract tar file: %v", err)
	}

	outputDir := filepath.Join(tempDir, strings.Split(filepath.Base(bundleFilePath), ".tar")[0])

	for _, file := range bundleFileList {
		if _, err := os.Stat(filepath.Join(outputDir, file)); os.IsNotExist(err) {
			os.RemoveAll(tempDir)
			return nil, fmt.Errorf("missing required file: %s, in %s", file, outputDir)
		}
	}

	ortSession, err := NewOrtSession(filepath.Join(outputDir, "model.onnx"))
	if err != nil {
		os.RemoveAll(tempDir)
		return nil, err
	}

	tokenizer, err := NewTokenizer(outputDir)
	if err != nil {
		ortSession.Close()
		os.RemoveAll(tempDir)
		return nil, err
	}

	inputShape := []int64{1, int64(tokenizer.modelMaxLength)}

	if err := os.RemoveAll(tempDir); err != nil {
		ortSession.Close()
		tokenizer.Close()
		return nil, fmt.Errorf("could not remove temp directory: %v", err)
	}

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
	options := EncodeOptions{
		AddSpecialTokens:    true,
		PadToMaxLength:      true, // TODO:= ONNX Input formats leads to segfault without this
		ReturnAttentionMask: true,
		Truncate:            true,
	}

	ids, _, attentionMask, err := pipeline.tokenizer.Encode(text, options)
	if err != nil {
		fmt.Println(err)
		fmt.Println("Error encoding text")
		return 0, err
	}

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

func extractTarFile(tarFilePath, outputDir string) error {
	file, err := os.Open(tarFilePath)
	if err != nil {
		return fmt.Errorf("could not open tar file: %v", err)
	}
	defer file.Close()

	tarReader := tar.NewReader(file)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading tar file: %v", err)
		}

		targetPath := filepath.Join(outputDir, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return fmt.Errorf("could not create directory %s: %v", targetPath, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("could not create directory %s: %v", filepath.Dir(targetPath), err)
			}

			outFile, err := os.Create(targetPath)
			if err != nil {
				return fmt.Errorf("could not create file %s: %v", targetPath, err)
			}

			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return fmt.Errorf("could not copy data to file %s: %v", targetPath, err)
			}
			outFile.Close()
		default:
			fmt.Printf("Unsupported file type in tar: %s\n", header.Name)
		}
	}
	return nil
}
