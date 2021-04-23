package file_acquisition

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	tomb "gopkg.in/tomb.v2"
)

func TestAcquisCat(t *testing.T) {

	tests := []struct {
		cfg DataSourceCfg
		//tombState
		config_error string
		read_error   string
		tomb_error   string
		lines        int
	}{
		{ //missing filename(s)
			cfg: DataSourceCfg{
				Mode: CAT_MODE,
			},
			config_error: "no filename or filenames",
		},
		{ //forbiden file
			cfg: DataSourceCfg{
				Mode:     CAT_MODE,
				Filename: "/etc/shadow",
			},
			config_error: "unable to open /etc/shadow : permission denied",
		},
		{ //bad regexp
			cfg: DataSourceCfg{
				Filename: "[a-",
				Mode:     CAT_MODE,
			},
			config_error: "while globbing [a-: syntax error in pattern",
		},
		{ //inexisting file
			cfg: DataSourceCfg{
				Filename: "/does/not/exists",
				Mode:     CAT_MODE,
			},
			config_error: "no files to read for [/does/not/exists]",
		},
		{ //ok file
			cfg: DataSourceCfg{
				Filename: "./tests/test.log",
				Mode:     CAT_MODE,
			},
			lines: 1,
		},
		{ //invalid gz
			cfg: DataSourceCfg{
				Filename: "./tests/badlog.gz",
				Mode:     CAT_MODE,
			},
			lines:      0,
			tomb_error: "failed to read gz ./tests/badlog.gz: EOF",
		},
		{ //good gz
			cfg: DataSourceCfg{
				Filename: "./tests/test.log.gz",
				Mode:     CAT_MODE,
			},
			lines: 1,
		},
	}

	for tidx, test := range tests {
		fileSrc := new(FileSource)
		err := fileSrc.Configure(test.cfg)
		if test.config_error != "" {
			assert.Contains(t, fmt.Sprintf("%s", err), test.config_error)
			log.Infof("expected config error ok : %s", test.config_error)
			continue
		} else {
			if err != nil {
				t.Fatalf("%d/%d unexpected config error %s", tidx, len(tests), err)
			}
		}

		out := make(chan types.Event)
		tomb := tomb.Tomb{}
		count := 0

		err = fileSrc.StartReading(out, &tomb)
		if test.read_error != "" {
			assert.Contains(t, fmt.Sprintf("%s", err), test.read_error)
			log.Infof("expected read error ok : %s", test.read_error)
			continue
		} else {
			if err != nil {
				t.Fatalf("%d/%d unexpected read error %s", tidx, len(tests), err)
			}
		}

	READLOOP:
		for {
			select {
			case <-out:
				count++
			case <-time.After(1 * time.Second):
				break READLOOP
			}
		}

		if count != test.lines {
			t.Fatalf("%d/%d expected %d line read, got %d", tidx, len(tests), test.lines, count)
		}

		if test.tomb_error != "" {
			assert.Contains(t, fmt.Sprintf("%s", tomb.Err()), test.tomb_error)
			log.Infof("expected tomb error ok : %s", test.read_error)
			continue
		} else {
			if tomb.Err() != nil {
				t.Fatalf("%d/%d unexpected tomb error %s", tidx, len(tests), tomb.Err())
			}
		}

	}

}

func TestTailKill(t *testing.T) {
	cfg := DataSourceCfg{
		Filename: "./tests/test.log",
		Mode:     TAIL_MODE,
	}

	fileSrc := new(FileSource)
	err := fileSrc.Configure(cfg)
	if err != nil {
		t.Fatalf("unexpected config error %s", err)
	}

	out := make(chan types.Event)
	tb := tomb.Tomb{}

	err = fileSrc.StartReading(out, &tb)
	if err != nil {
		t.Fatalf("unexpected read error %s", err)
	}
	time.Sleep(1 * time.Second)
	if tb.Err() != tomb.ErrStillAlive {
		t.Fatalf("unexpected tomb error %s (should be alive)", tb.Err())
	}
	//kill it :>
	tb.Kill(nil)
	time.Sleep(1 * time.Second)
	if tb.Err() != nil {
		t.Fatalf("unexpected tomb error %s (should be dead)", tb.Err())
	}

}

func TestTailKillBis(t *testing.T) {
	cfg := DataSourceCfg{
		Filename: "./tests/test.log",
		Mode:     TAIL_MODE,
	}

	fileSrc := new(FileSource)
	err := fileSrc.Configure(cfg)
	if err != nil {
		t.Fatalf("unexpected config error %s", err)
	}

	out := make(chan types.Event)
	tb := tomb.Tomb{}

	err = fileSrc.StartReading(out, &tb)
	if err != nil {
		t.Fatalf("unexpected read error %s", err)
	}
	time.Sleep(1 * time.Second)
	if tb.Err() != tomb.ErrStillAlive {
		t.Fatalf("unexpected tomb error %s (should be alive)", tb.Err())
	}
	//kill the underlying tomb of tailer
	fileSrc.tails[0].Kill(fmt.Errorf("ratata"))
	time.Sleep(1 * time.Second)
	//it can be two errors :
	if !strings.Contains(fmt.Sprintf("%s", tb.Err()), "dead reader for ./tests/test.log") &&
		!strings.Contains(fmt.Sprintf("%s", tb.Err()), "tail for ./tests/test.log is empty") {
		t.Fatalf("unexpected error : %s", tb.Err())
	}

}

func TestTailRuntime(t *testing.T) {
	//log.SetLevel(log.TraceLevel)

	cfg := DataSourceCfg{
		Filename: "./tests/test.log",
		Mode:     TAIL_MODE,
	}

	fileSrc := new(FileSource)
	err := fileSrc.Configure(cfg)
	if err != nil {
		t.Fatalf("unexpected config error %s", err)
	}

	out := make(chan types.Event)
	tb := tomb.Tomb{}
	count := 0

	err = fileSrc.StartReading(out, &tb)
	if err != nil {
		t.Fatalf("unexpected read error %s", err)
	}

	time.Sleep(1 * time.Second)
	//write data
	f, err := os.OpenFile(cfg.Filename, os.O_APPEND|os.O_WRONLY, 0644)
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

READLOOP:
	for {
		select {
		case <-out:
			count++
		case <-time.After(1 * time.Second):
			break READLOOP
		}
	}

	if count != 5 {
		t.Fatalf("expected %d line read, got %d", 5, count)
	}

	if tb.Err() != tomb.ErrStillAlive {
		t.Fatalf("unexpected tomb error %s", tb.Err())
	}

	/*reset the file*/
	f, err = os.OpenFile(cfg.Filename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("one log line\n")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func TestAcquisTail(t *testing.T) {

	tests := []struct {
		cfg DataSourceCfg
		//tombState
		config_error string
		read_error   string
		tomb_error   string
		lines        int
	}{
		{ //missing filename(s)
			cfg: DataSourceCfg{
				Mode: TAIL_MODE,
			},
			config_error: "no filename or filenames",
		},
		{ //forbiden file
			cfg: DataSourceCfg{
				Mode:     TAIL_MODE,
				Filename: "/etc/shadow",
			},
			config_error: "unable to open /etc/shadow : permission denied",
		},
		{ //bad regexp
			cfg: DataSourceCfg{
				Filename: "[a-",
				Mode:     TAIL_MODE,
			},
			config_error: "while globbing [a-: syntax error in pattern",
		},
		{ //inexisting file
			cfg: DataSourceCfg{
				Filename: "/does/not/exists",
				Mode:     TAIL_MODE,
			},
			config_error: "no files to read for [/does/not/exists]",
		},
		{ //ok file
			cfg: DataSourceCfg{
				Filename: "./tests/test.log",
				Mode:     TAIL_MODE,
			},
			lines:      0,
			tomb_error: "still alive",
		},
		{ //invalid gz
			cfg: DataSourceCfg{
				Filename: "./tests/badlog.gz",
				Mode:     TAIL_MODE,
			},
			lines:      0,
			tomb_error: "still alive",
		},
		{ //good gz
			cfg: DataSourceCfg{
				Filename: "./tests/test.log.gz",
				Mode:     TAIL_MODE,
			},
			lines:      0,
			tomb_error: "still alive",
		},
	}

	for tidx, test := range tests {
		fileSrc := new(FileSource)
		err := fileSrc.Configure(test.cfg)
		if test.config_error != "" {
			assert.Contains(t, fmt.Sprintf("%s", err), test.config_error)
			log.Infof("expected config error ok : %s", test.config_error)
			continue
		} else {
			if err != nil {
				t.Fatalf("%d/%d unexpected config error %s", tidx, len(tests), err)
			}
		}

		out := make(chan types.Event)
		tomb := tomb.Tomb{}
		count := 0

		err = fileSrc.StartReading(out, &tomb)
		if test.read_error != "" {
			assert.Contains(t, fmt.Sprintf("%s", err), test.read_error)
			log.Infof("expected read error ok : %s", test.read_error)
			continue
		} else {
			if err != nil {
				t.Fatalf("%d/%d unexpected read error %s", tidx, len(tests), err)
			}
		}

	READLOOP:
		for {
			select {
			case <-out:
				count++
			case <-time.After(1 * time.Second):
				break READLOOP
			}
		}

		if count != test.lines {
			t.Fatalf("%d/%d expected %d line read, got %d", tidx, len(tests), test.lines, count)
		}

		if test.tomb_error != "" {
			assert.Contains(t, fmt.Sprintf("%s", tomb.Err()), test.tomb_error)
			log.Infof("expected tomb error ok : %s", test.read_error)
			continue
		} else {
			if tomb.Err() != nil {
				t.Fatalf("%d/%d unexpected tomb error %s", tidx, len(tests), tomb.Err())
			}
		}

	}

}
