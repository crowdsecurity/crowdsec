package acquisition

import (
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/stretchr/testify/assert"
	"gopkg.in/tomb.v2"
)

func TestLoadAcquisitionConfig(t *testing.T) {
	testFilePath := "./tests/test.log"

	tests := []struct {
		csConfig *csconfig.CrowdSec
		result   *FileAcquisCtx
		err      string
	}{
		{
			csConfig: &csconfig.CrowdSec{
				SingleFile:      testFilePath,
				SingleFileLabel: "my_test_log",
				Profiling:       false,
			},
			result: &FileAcquisCtx{
				Files: []FileCtx{
					{
						Type:      "file",
						Mode:      "cat",
						Filename:  testFilePath,
						Filenames: []string{},
						Labels: map[string]string{
							"type": "my_test_log",
						},
						Profiling: false,
					},
				},
				Profiling: false,
			},
			err: "",
		},
		{
			csConfig: &csconfig.CrowdSec{
				SingleFile:      testFilePath,
				SingleFileLabel: "my_test_log",
				Profiling:       true,
			},
			result: &FileAcquisCtx{
				Files: []FileCtx{
					{
						Type:      "file",
						Mode:      "cat",
						Filename:  testFilePath,
						Filenames: []string{},
						Labels: map[string]string{
							"type": "my_test_log",
						},
						Profiling: false,
					},
				},
				Profiling: true,
			},
			err: "",
		},
	}

	for _, test := range tests {
		result, err := LoadAcquisitionConfig(test.csConfig)
		assert.Equal(t, test.result, result)
		if test.err == "" && err == nil {
			continue
		}
		assert.EqualError(t, err, test.err)
	}
}

func TestAcquisStartReading(t *testing.T) {
	// Test in TAIL mode
	acquisFilePath := "./tests/acquis_test_log.yaml"
	csConfig := &csconfig.CrowdSec{
		AcquisitionFile: acquisFilePath,
		Profiling:       false,
	}
	fCTX, err := LoadAcquisitionConfig(csConfig)
	if err != nil {
		t.Fatalf(err.Error())
	}
	outputChan := make(chan types.Event)
	acquisTomb := tomb.Tomb{}

	AcquisStartReading(fCTX, outputChan, &acquisTomb)
	if !acquisTomb.Alive() {
		t.Fatal("acquisition tomb is not alive")
	}

	// Test in CAT mode
	testFilePath := "./tests/test.log"

	csConfig = &csconfig.CrowdSec{
		SingleFile:      testFilePath,
		SingleFileLabel: "my_test_log",
		Profiling:       false,
	}

	fCTX, err = LoadAcquisitionConfig(csConfig)
	if err != nil {
		t.Fatalf(err.Error())
	}
	outputChan = make(chan types.Event)
	acquisTomb = tomb.Tomb{}

	AcquisStartReading(fCTX, outputChan, &acquisTomb)
	if !acquisTomb.Alive() {
		t.Fatal("acquisition tomb is not alive")
	}

	// Test with a .gz file
	testFilePath = "./tests/test.log.gz"

	csConfig = &csconfig.CrowdSec{
		SingleFile:      testFilePath,
		SingleFileLabel: "my_test_log",
		Profiling:       false,
	}

	fCTX, err = LoadAcquisitionConfig(csConfig)
	if err != nil {
		t.Fatalf(err.Error())
	}
	outputChan = make(chan types.Event)
	acquisTomb = tomb.Tomb{}

	AcquisStartReading(fCTX, outputChan, &acquisTomb)
	if !acquisTomb.Alive() {
		t.Fatal("acquisition tomb is not alive")
	}

}
