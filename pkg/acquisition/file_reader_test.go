package acquisition

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
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

func TestAcquisStartReadingTailKilled(t *testing.T) {
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

	time.Sleep(500 * time.Millisecond)
	filename := "./tests/test.log"

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		_, err := f.WriteString(fmt.Sprintf("ratata%d\n", i))
		if err != nil {
			t.Fatal(err)
		}
	}
	f.Close()

	time.Sleep(500 * time.Millisecond)
	reads := 0
L:
	for {
		select {
		case <-outputChan:
			reads++
			if reads == 2 {
				acquisTomb.Kill(nil)
				time.Sleep(100 * time.Millisecond)
			}
		case <-time.After(1 * time.Second):
			break L
		}
	}

	log.Printf("-> %d", reads)
	if reads != 2 {
		t.Fatal()
	}

	f, err = os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("one log line\n")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func TestAcquisStartReadingTail(t *testing.T) {
	acquisFilePath := "./tests/acquis_test_log.yaml"
	filename := "./tests/test.log"
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

	time.Sleep(500 * time.Millisecond)

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		_, err := f.WriteString(fmt.Sprintf("ratata%d\n", i))
		if err != nil {
			t.Fatal(err)
		}
	}
	f.Close()

	time.Sleep(500 * time.Millisecond)
	reads := 0
L:
	for {
		select {
		case <-outputChan:
			reads++
			//log.Printf("evt %+v", evt)
		case <-time.After(1 * time.Second):
			break L
		}
	}

	log.Printf("-> %d", reads)
	if reads != 5 {
		t.Fatal()
	}

	acquisTomb.Kill(nil)
	if err := acquisTomb.Wait(); err != nil {
		t.Fatalf("Acquisition returned error : %s", err)
	}

	f, err = os.OpenFile(filename, os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("one log line\n")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func TestAcquisStartReadingCat(t *testing.T) {
	testFilePath := "./tests/test.log"

	f, err := os.OpenFile(testFilePath, os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		_, err := f.WriteString(fmt.Sprintf("ratata%d\n", i))
		if err != nil {
			t.Fatal(err)
		}
	}
	f.Close()

	csConfig := &csconfig.CrowdSec{
		SingleFile:      testFilePath,
		SingleFileLabel: "my_test_log",
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

	time.Sleep(500 * time.Millisecond)
	reads := 0
L:
	for {
		select {
		case <-outputChan:
			reads++
		case <-time.After(1 * time.Second):
			break L
		}
	}

	log.Printf("-> %d", reads)
	if reads != 5 {
		t.Fatal()
	}

	acquisTomb.Kill(nil)
	if err := acquisTomb.Wait(); err != nil {
		t.Fatalf("Acquisition returned error : %s", err)
	}

	f, err = os.OpenFile(testFilePath, os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("one log line\n")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func TestAcquisStartReadingGzCat(t *testing.T) {
	testFilePath := "./tests/test.log.gz"

	csConfig := &csconfig.CrowdSec{
		SingleFile:      testFilePath,
		SingleFileLabel: "my_test_log",
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

	time.Sleep(500 * time.Millisecond)
	reads := 0
L:
	for {
		select {
		case <-outputChan:
			reads++
		case <-time.After(1 * time.Second):
			break L
		}
	}

	log.Printf("-> %d", reads)
	if reads != 1 {
		t.Fatal()
	}
}
