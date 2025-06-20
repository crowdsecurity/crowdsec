package ml

import (
	"fmt"
	"log"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func BenchmarkPredictLabel(b *testing.B) {
	log.Println("Starting benchmark for PredictLabel")

	tarFilePath := "testdata/anomaly_detection_bundle_test.tar"

	pipeline, err := NewRobertaInferencePipeline(tarFilePath)
	if err != nil {
		b.Fatalf("NewRobertaInferencePipeline returned error: %v", err)
	}
	defer pipeline.Close()

	text := "POST /"

	b.ResetTimer()
	startTime := time.Now()

	for n := 0; n < b.N; n++ {
		if n%1000 == 0 {
			log.Printf("Running iteration %d", n)
		}

		_, err := pipeline.PredictLabel(text)
		if err != nil {
			b.Fatalf("Prediction failed: %v", err)
		}
	}

	var memStart runtime.MemStats
	runtime.ReadMemStats(&memStart)

	for n := 0; n < b.N; n++ {
		_, err := pipeline.PredictLabel(text)
		if err != nil {
			b.Fatalf("Prediction failed: %v", err)
		}
	}

	b.StopTimer()

	var memEnd runtime.MemStats
	runtime.ReadMemStats(&memEnd)

	totalAlloc := memEnd.TotalAlloc - memStart.TotalAlloc
	allocPerOp := totalAlloc / uint64(b.N)

	totalTime := time.Since(startTime)
	log.Printf("Total benchmark time: %s\n", totalTime)
	log.Printf("Average time per prediction: %s\n", totalTime/time.Duration(b.N))
	log.Printf("Number of operations: %d\n", b.N)
	log.Printf("Operations per second: %.2f ops/s\n", float64(b.N)/totalTime.Seconds())
	log.Printf("Memory allocated per operation: %d bytes\n", allocPerOp)
	log.Printf("Total memory allocated: %d bytes\n", totalAlloc)

	fmt.Printf("Benchmark Results:\n")
	fmt.Printf("  Total time: %s\n", totalTime)
	fmt.Printf("  Average time per operation: %s\n", totalTime/time.Duration(b.N))
	fmt.Printf("  Operations per second: %.2f ops/s\n", float64(b.N)/totalTime.Seconds())
	fmt.Printf("  Memory allocated per operation: %d bytes\n", allocPerOp)
	fmt.Printf("  Total memory allocated: %d bytes\n", totalAlloc)
}
func TestPredictLabel(t *testing.T) {
	tests := []struct {
		name       string
		text       string
		expectedID int
		label      int
	}{
		{
			name:       "Malicious request",
			text:       "GET /lib/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php?",
			expectedID: 0,
			label:      1,
		},
		{
			name:       "Safe request",
			text:       "GET /online/_ui/responsive/theme-miglog/img/header+Navigation/icon-delivery.svg",
			expectedID: 0,
			label:      0,
		},
	}

	tarFilePath := "testdata/anomaly_detection_bundle_test.tar"

	pipeline, err := NewRobertaInferencePipeline(tarFilePath)
	if err != nil {
		t.Fatalf("NewRobertaInferencePipeline returned error: %v", err)
	}
	defer pipeline.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prediction, err := pipeline.PredictLabel(tt.text)
			if err != nil {
				t.Errorf("PredictLabel returned error: %v", err)
			}

			assert.Equal(t, tt.label, prediction, "Predicted label does not match the expected label")
		})
	}
}
