package acquisition

import (
	"fmt"
	"os"
	"strings"
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

func TestAcquisStartReadingErrors(t *testing.T) {

	//test: empty files
	test := FileAcquisCtx{
		Profiling: true,
	}
	outputChan := make(chan types.Event)
	acquisTomb := tomb.Tomb{}

	if err := AcquisStartReading(&test, outputChan, &acquisTomb); err != nil {
		if !strings.HasPrefix(fmt.Sprintf("%s", err), "no files to read") {
			t.Fatalf("error mismatch")
		}
	} else {
		t.Fatalf("expected error")
	}

	//test: bad read mode
	test = FileAcquisCtx{
		Profiling: true,
		Files: []FileCtx{
			FileCtx{
				Type:     "",
				Mode:     "unknown",
				Filename: "./tests/test.log",
			},
		},
	}
	outputChan = make(chan types.Event)
	acquisTomb = tomb.Tomb{}

	if err := AcquisStartReading(&test, outputChan, &acquisTomb); err != nil {
		if !strings.HasPrefix(fmt.Sprintf("%s", err), "unknown read mode unknown") {
			t.Fatalf("error mismatch")
		}
	} else {
		t.Fatalf("expected error")
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

func recreateTestFile(fname string) {
	f, err := os.OpenFile(fname, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		_, err := f.WriteString(fmt.Sprintf("ratata%d\n", i))
		if err != nil {
			log.Fatal(err)
		}
	}

	f.Close()
}

func TestLoadAcquisCtxConfigFile(t *testing.T) {
	tests := []struct {
		cfg    csconfig.CrowdsecServiceCfg
		result []FileCtx
		err    string
	}{
		{
			cfg: csconfig.CrowdsecServiceCfg{},
			err: "missing config or acquisition file path",
		},
		{
			cfg: csconfig.CrowdsecServiceCfg{AcquisitionFilePath: "/doesnt/exist"},
			err: "can't open /doesnt/exist: open /doesnt",
		},
		{
			cfg: csconfig.CrowdsecServiceCfg{AcquisitionFilePath: "/etc/passwd"},
			err: "failed to yaml decode /etc/passwd",
		},
	}

	for _, test := range tests {
		res, err := LoadAcquisCtxConfigFile(&test.cfg)
		if test.err != "" {
			if !strings.HasPrefix(fmt.Sprintf("%s", err), test.err) {
				t.Fatalf("mismatch error : %s expected %s", err, test.err)
			}
		}
		if test.err == "" && err != nil {
			t.Fatalf("unexpected error, got %s", err)
		}
		assert.Equal(t, test.result, res)
	}

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

	recreateTestFile(testFilePath)

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

	f, err := os.OpenFile(testFilePath, os.O_TRUNC|os.O_WRONLY, 0644)
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

func TestCatFileErrors(t *testing.T) {
	tests := []struct {
		Config FileCtx
		err    string
	}{
		{
			Config: FileCtx{
				Type:     FILETYPE,
				Mode:     CATMODE,
				Filename: "./tests/test.log",
				Labels: map[string]string{
					"type": "ratata",
				},
			},
			//err: "rata",
		},

		{ //error : multi file
			Config: FileCtx{
				Type:      FILETYPE,
				Mode:      CATMODE,
				Filenames: []string{"./tests/test.log", "xxuuu"},
				Labels: map[string]string{
					"type": "ratata",
				},
			},
			err: "no multi-file support for this mode",
		},

		{ //error : unreadable file
			Config: FileCtx{
				Type:     FILETYPE,
				Mode:     CATMODE,
				Filename: "./tests/notexist.log",
				Labels: map[string]string{
					"type": "ratata",
				},
			},
			err: "failed opening ./tests/notexist.log:",
		},

		{ //error : bad gz file
			Config: FileCtx{
				Type:     FILETYPE,
				Mode:     CATMODE,
				Filename: "./tests/badlog.gz",
				Labels: map[string]string{
					"type": "ratata",
				},
			},
			err: "failed to read gz ./tests/badlog.gz: ",
		},
	}

	for _, test := range tests {
		outputChan := make(chan types.Event)
		acquisTomb := tomb.Tomb{}

		go func(msg chan types.Event) {
			time.Sleep(500 * time.Millisecond)
		L:
			for {
				select {
				case x := <-msg:
					log.Printf("got '%+v'", x)
				default:
					break L
				}
			}
			fmt.Printf("bye")
		}(outputChan)

		err := CatFile(test.Config, outputChan, &acquisTomb)
		if err != nil && test.err == "" {
			t.Fatalf("unexpected error : %s", err)
		}
		if err != nil && test.err != "" {
			if !strings.HasPrefix(fmt.Sprintf("%s", err), test.err) {
				t.Fatalf("expected '%s' got '%s'", test.err, err)
			}
		}
		if err == nil && test.err != "" {
			t.Fatalf("expected error %s, didn't got", test.err)
		}
	}
}

func TestInitReaderFromFileCtxConfigs(t *testing.T) {
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
			err:    "no filename in {Type:file",
		},

		{ //test error - no tag
			Config: []FileCtx{FileCtx{
				Type:     FILETYPE,
				Mode:     CATMODE,
				Filename: "./tests/test.log",
				Labels:   map[string]string{
					//"type": "ratata",
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
			err: "no tags in {Type:fil",
		},

		{ //test error - no glob result, no error
			Config: []FileCtx{FileCtx{
				Type:     FILETYPE,
				Mode:     CATMODE,
				Filename: "./tests/*notexits*",
				Labels: map[string]string{
					"type": "ratata",
				},
			}},
			Result: &FileAcquisCtx{
				Profiling: false,
			},
		},

		{ //test error - glob error
			Config: []FileCtx{FileCtx{
				Type:     FILETYPE,
				Mode:     CATMODE,
				Filename: "./tests/*[notexits*",
				Labels: map[string]string{
					"type": "ratata",
				},
			}},
			Result: &FileAcquisCtx{
				Profiling: false,
			},
			err: "while globbing ./tests/*[notexits*: syntax error in pattern",
		},

		{ //test error - bad type
			Config: []FileCtx{FileCtx{
				Type:     "RATATATA",
				Mode:     CATMODE,
				Filename: "./tests/test.log",
				Labels: map[string]string{
					"type": "ratata",
				},
			}},
			Result: &FileAcquisCtx{
				Profiling: false,
			},
			err: "./tests/test.log is of unknown type RATATATA",
		},

		{ //test error - can't access file
			Config: []FileCtx{FileCtx{
				Type:     FILETYPE,
				Mode:     CATMODE,
				Filename: "/etc/shadow",
				Labels: map[string]string{
					"type": "ratata",
				},
			}},
			Result: &FileAcquisCtx{
				Profiling: false,
			},
			//err: "./tests/test.log is of unknown type RATATATA",
		},
	}

	for testidx, test := range tests {
		AcqCtx, err := InitReaderFromFileCtx(test.Config)
		if err != nil && test.err == "" {
			t.Fatalf("unexpected error : %s", err)
		}
		if err != nil && test.err != "" {
			if !strings.HasPrefix(fmt.Sprintf("%s", err), test.err) {
				t.Fatalf("expected '%s' got '%s'", test.err, err)
			}
		}
		if err == nil && test.err != "" {
			t.Fatalf("expected error %s, didn't got", test.err)
		}

		if AcqCtx == nil {
			continue
		}
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
