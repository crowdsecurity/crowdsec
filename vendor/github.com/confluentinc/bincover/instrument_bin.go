package bincover

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"runtime/debug"
	"strings"
	"testing"
)

var (
	argsFilename = flag.String("args-file", "", "custom args file, newline separated")
	ExitCode     = 0
)

const (
	startOfMetadataMarker = "START_BINCOVER_METADATA"
	endOfMetadataMarker   = "END_BINCOVER_METADATA"
)

func parseCustomArgs() ([]string, error) {
	buf, err := ioutil.ReadFile(*argsFilename)
	if err != nil {
		return nil, err
	}
	rawArgs := strings.Split(string(buf), "\n")
	var parsedCustomArgs []string
	for _, arg := range rawArgs {
		arg = strings.TrimSpace(arg)
		if len(arg) > 0 {
			parsedCustomArgs = append(parsedCustomArgs, arg)
		}
	}
	return parsedCustomArgs, nil
}

type testMetadata struct {
	CoverMode string `json:"cover_mode"`
	ExitCode  int    `json:"exit_code"`
}

func printMetadata(metadata *testMetadata) {
	fmt.Println(startOfMetadataMarker)
	b, err := json.Marshal(metadata)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(b))
	fmt.Println(endOfMetadataMarker)
}

// RunTest runs function f (usually main), with arguments specified by the flag "args-file", a file of newline-separated args.
// When f runs to completion (success or failure), RunTest prints (newline-separated):
// 1. f's output,
// 2. startOfMetadataMarker
// 3. a testMetadata struct
// 4. endOfMetadataMarker
//
// Otherwise, if an unexpected error is encountered during execution, RunTest panics.
func RunTest(f func()) {
	if !flag.Parsed() {
		flag.Parse()
	}
	var parsedArgs []string
	for _, arg := range os.Args {
		if !strings.HasPrefix(arg, "-test.") && !strings.HasPrefix(arg, "-args-file") {
			parsedArgs = append(parsedArgs, arg)
		}
	}
	if len(*argsFilename) > 0 {
		customArgs, err := parseCustomArgs()
		if err != nil {
			panic(err)
		}
		parsedArgs = append(parsedArgs, customArgs...)
	}
	os.Args = parsedArgs
	// Catch panicking binaries.
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("panic: %s\n%s", r, debug.Stack())
			ExitCode = 1
		}
		metadata := &testMetadata{
			CoverMode: testing.CoverMode(),
			ExitCode:  ExitCode,
		}
		printMetadata(metadata)
	}()
	f()
}
