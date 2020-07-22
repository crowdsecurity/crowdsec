package acquisition

import (
	"fmt"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"gotest.tools/assert"
)

func TestLoadAcquisitionConfig(t *testing.T) {
	tests := []struct {
		csConfig *csconfig.CrowdSec
		result   *FileAcquisCtx
		err      error
	}{
		{
			csConfig: &csconfig.CrowdSec{
				SingleFile:      "./tests/test.log",
				SingleFileLabel: "my_test_log",
				Profiling:       false,
			},
			result: &FileAcquisCtx{
				Files: []FileCtx{
					{
						Type:     "file",
						Mode:     "cat",
						Filename: "./tests/test.log",
						Labels: map[string]string{
							"type": "my_test_log",
						},
						Profiling: false,
					},
				},
			},
			err: nil,
		},
	}

	for _, test := range tests {
		result, err := LoadAcquisitionConfig(test.csConfig)
		fmt.Printf("result : %+v\n", result)
		fmt.Printf("test : %+v \n", test.result)
		assert.Equal(t, test.result, result)
		assert.Equal(t, test.err, err)
	}
}
