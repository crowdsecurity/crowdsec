package ml

import (
	"fmt"
	"log"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func BenchmarkPredictLabel(b *testing.B) {
	// Log the start of the benchmark
	log.Println("Starting benchmark for PredictLabel")

	// Initialize the Roberta Inference Pipeline once
	pipeline, err := NewRobertaInferencePipeline(filepath.Join("/Users/davidlequin/models"))
	if err != nil {
		b.Fatalf("Failed to initialize pipeline: %v", err)
	}
	defer pipeline.Close()

	// The text to use for benchmarking
	text := "POST /"

	// Reset the timer to exclude setup time from the benchmark
	b.ResetTimer()
	startTime := time.Now()

	// Run the benchmark loop
	for n := 0; n < b.N; n++ {
		// Log each iteration if needed (optional)
		if n%1000 == 0 {
			log.Printf("Running iteration %d", n)
		}

		_, err := pipeline.PredictLabel(text)
		if err != nil {
			b.Fatalf("Prediction failed: %v", err)
		}
	}

	// Start measuring memory before the benchmark loop
	var memStart runtime.MemStats
	runtime.ReadMemStats(&memStart)

	// Run the benchmark loop
	for n := 0; n < b.N; n++ {
		_, err := pipeline.PredictLabel(text)
		if err != nil {
			b.Fatalf("Prediction failed: %v", err)
		}
	}

	b.StopTimer()

	// Measure memory after the benchmark loop
	var memEnd runtime.MemStats
	runtime.ReadMemStats(&memEnd)

	// Calculate memory usage
	totalAlloc := memEnd.TotalAlloc - memStart.TotalAlloc
	allocPerOp := totalAlloc / uint64(b.N)

	// Human-readable summary
	b.ReportAllocs() // Report memory allocations
	totalTime := time.Since(startTime)
	log.Printf("Total benchmark time: %s\n", totalTime)
	log.Printf("Average time per prediction: %s\n", totalTime/time.Duration(b.N))
	log.Printf("Number of operations: %d\n", b.N)
	log.Printf("Operations per second: %.2f ops/s\n", float64(b.N)/totalTime.Seconds())
	log.Printf("Memory allocated per operation: %d bytes\n", allocPerOp)
	log.Printf("Total memory allocated: %d bytes\n", totalAlloc)

	// Output results in a human-readable format
	fmt.Printf("Benchmark Results:\n")
	fmt.Printf("  Total time: %s\n", totalTime)
	fmt.Printf("  Average time per operation: %s\n", totalTime/time.Duration(b.N))
	fmt.Printf("  Operations per second: %.2f ops/s\n", float64(b.N)/totalTime.Seconds())
	fmt.Printf("  Memory allocated per operation: %d bytes\n", allocPerOp)
	fmt.Printf("  Total memory allocated: %d bytes\n", totalAlloc)

}
