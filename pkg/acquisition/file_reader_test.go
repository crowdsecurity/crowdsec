package acquisition

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/nxadm/tail"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	tomb "gopkg.in/tomb.v2"
)

func TestLoadAcquisitionSingleFile(t *testing.T) {
	testFilePath := "./tests/test.log"

	tests := []struct {
		fname  string
		ftype  string
		result *FileAcquisCtx
		err    string
	}{
		{
			fname: testFilePath,
			ftype: "my_test_log",
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
	}

	for _, test := range tests {
		ctx, err := LoadAcquisCtxSingleFile(test.fname, test.ftype)
		result, err := InitReaderFromFileCtx(ctx)
		//result, err := LoadAcquisitionConfig(test.csConfig)
		assert.Equal(t, test.result, result)
		if test.err == "" && err == nil {
			continue
		}
		assert.EqualError(t, err, test.err)
	}
}

func TestAcquisStartReadingTailKilled(t *testing.T) {
	acquisFilePath := "./tests/acquis_test.yaml"
	testFilePath := "./tests/test.log"

	csConfig := &csconfig.CrowdsecServiceCfg{
		AcquisitionFilePath: acquisFilePath,
	}

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

	fCTX, err := LoadAcquisCtxConfigFile(csConfig)
	if err != nil {
		t.Fatalf(err.Error())
	}
	outputChan := make(chan types.Event)
	acquisTomb := tomb.Tomb{}

	acquisCtx, err := InitReaderFromFileCtx(fCTX)
	if err != nil {
		t.Fatalf(err.Error())
	}
	if err := AcquisStartReading(acquisCtx, outputChan, &acquisTomb); err != nil {
		t.Fatalf("while AcquisStartReading: %s", err)
	}
	if !acquisTomb.Alive() {
		t.Fatal("acquisition tomb is not alive")
	}

	time.Sleep(500 * time.Millisecond)
	filename := "./tests/test.log"

	f, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0644)
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
	acquisFilePath := "./tests/acquis_test.yaml"
	filename := "./tests/test.log"
	csConfig := &csconfig.CrowdsecServiceCfg{
		AcquisitionFilePath: acquisFilePath,
	}
	fCTX, err := LoadAcquisCtxConfigFile(csConfig)
	if err != nil {
		t.Fatalf(err.Error())
	}
	outputChan := make(chan types.Event)
	acquisTomb := tomb.Tomb{}

	acquisCtx, err := InitReaderFromFileCtx(fCTX)
	if err != nil {
		t.Fatalf(err.Error())
	}
	if err := AcquisStartReading(acquisCtx, outputChan, &acquisTomb); err != nil {
		t.Fatalf("AcquisStartReading : %s", err)
	}
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

	ctx, err := LoadAcquisCtxSingleFile(testFilePath, "my_test_log")
	if err != nil {
		t.Fatalf("LoadAcquisCtxSingleFile")
	}
	fCTX, err := InitReaderFromFileCtx(ctx)
	if err != nil {
		t.Fatalf("InitReaderFromFileCtx")
	}
	outputChan := make(chan types.Event)
	acquisTomb := tomb.Tomb{}
	if err := AcquisStartReading(fCTX, outputChan, &acquisTomb); err != nil {
		t.Fatalf("AcquisStartReading : %s", err)
	}
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

	ctx, err := LoadAcquisCtxSingleFile(testFilePath, "my_test_log")
	if err != nil {
		t.Fatalf("LoadAcquisCtxSingleFile")
	}
	fCTX, err := InitReaderFromFileCtx(ctx)
	if err != nil {
		t.Fatalf("InitReaderFromFileCtx")
	}
	outputChan := make(chan types.Event)
	acquisTomb := tomb.Tomb{}
	if err := AcquisStartReading(fCTX, outputChan, &acquisTomb); err != nil {
		t.Fatalf("AcquisStartReading : %s", err)
	}
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

func TestCatFromAcquisStruct(t *testing.T) {
	tests := []struct {
		Config []FileCtx
		Result *FileAcquisCtx
		err    string
	}{
		{
			Config: []FileCtx{FileCtx{
				Type:     FILETYPE,
				Mode:     CATMODE,
				Filename: "./tests/test.log",
				Labels: map[string]string{
					"type": "ratata",
				},
			}},
			Result: &FileAcquisCtx{
				Files: []FileCtx{
					FileCtx{Type: "file",
						Mode:      "cat",
						Filename:  "./tests/test.log",
						Filenames: []string{},
						tail:      nil,
						Labels: map[string]string{
							"type": "ratata"},
						Profiling: false,
					},
				},
				Profiling: false,
			},
		},

		{
			Config: []FileCtx{FileCtx{
				Type: FILETYPE,
				//Mode:     CATMODE,
				Filename: "./tests/test.log",
				Labels: map[string]string{
					"type": "ratata",
				},
			}},
			Result: &FileAcquisCtx{
				Files: []FileCtx{
					FileCtx{Type: "file",
						Mode:      "tail",
						Filename:  "./tests/test.log",
						Filenames: []string{},
						tail:      &tail.Tail{},
						Labels: map[string]string{
							"type": "ratata"},
						Profiling: false,
					},
				},
				Profiling: false,
			},
		},

		{
			Config: []FileCtx{FileCtx{
				//Type: FILETYPE,
				//Mode:     CATMODE,
				Filename: "./tests/test.log",
				Labels: map[string]string{
					"type": "ratata",
				},
			}},
			Result: &FileAcquisCtx{
				Files: []FileCtx{
					FileCtx{Type: "file",
						Mode:      "tail",
						Filename:  "./tests/test.log",
						Filenames: []string{},
						tail:      &tail.Tail{},
						Labels: map[string]string{
							"type": "ratata"},
						Profiling: false,
					},
				},
				Profiling: false,
			},
		},

		{
			Config: []FileCtx{FileCtx{
				Type: FILETYPE,
				//Mode:     CATMODE,
				Filename: "",
				Labels: map[string]string{
					"type": "ratata",
				},
			}},
			Result: &FileAcquisCtx{},
		},
	}

	for testidx, test := range tests {
		AcqCtx, err := InitReaderFromFileCtx(test.Config)
		//we can't compare the tail object, it's not ours, just check non-nil
		for ridx, res := range AcqCtx.Files {
			if res.tail == nil {
				if test.Result.Files[ridx].tail != nil {
					t.Fatalf("(%d/%d) expected nil tail, got non-nil tail", testidx, len(tests))
				}
			}
			if res.tail != nil {
				if test.Result.Files[ridx].tail == nil {
					t.Fatalf("(%d/%d) expected non-nil tail, got nil tail", testidx, len(tests))
				}
			}
			test.Result.Files[ridx].tail = nil
			AcqCtx.Files[ridx].tail = nil
		}
		assert.Equal(t, test.Result, AcqCtx)
		if test.err == "" && err == nil {
			continue
		}
		log.Printf("->%s", err)
		assert.EqualError(t, err, test.err)
	}

}
