package journalctlacquisition

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/crowdsecurity/go-cs-lib/pkg/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"gopkg.in/tomb.v2"
)

func TestBadConfiguration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on windows")
	}
	tests := []struct {
		config      string
		expectedErr string
	}{
		{
			config:      `foobar: asd.log`,
			expectedErr: "line 1: field foobar not found in type journalctlacquisition.JournalCtlConfiguration",
		},
		{
			config: `
mode: tail
source: journalctl`,
			expectedErr: "journalctl_filter is required",
		},
		{
			config: `
mode: cat
source: journalctl
journalctl_filter:
 - _UID=42`,
			expectedErr: "",
		},
	}

	subLogger := log.WithFields(log.Fields{
		"type": "journalctl",
	})
	for _, test := range tests {
		f := JournalCtlSource{}
		err := f.Configure([]byte(test.config), subLogger)
		cstest.AssertErrorContains(t, err, test.expectedErr)
	}
}

func TestConfigureDSN(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on windows")
	}
	tests := []struct {
		dsn         string
		expectedErr string
	}{
		{
			dsn:         "asd://",
			expectedErr: "invalid DSN asd:// for journalctl source, must start with journalctl://",
		},
		{
			dsn:         "journalctl://",
			expectedErr: "empty journalctl:// DSN",
		},
		{
			dsn:         "journalctl://foobar=42",
			expectedErr: "unsupported key foobar in journalctl DSN",
		},
		{
			dsn:         "journalctl://filters=%ZZ",
			expectedErr: "could not parse journalctl DSN : invalid URL escape \"%ZZ\"",
		},
		{
			dsn:         "journalctl://filters=_UID=42?log_level=warn",
			expectedErr: "",
		},
		{
			dsn:         "journalctl://filters=_UID=1000&log_level=foobar",
			expectedErr: "unknown level foobar: not a valid logrus Level:",
		},
		{
			dsn:         "journalctl://filters=_UID=1000&log_level=warn&since=yesterday",
			expectedErr: "",
		},
	}
	subLogger := log.WithFields(log.Fields{
		"type": "journalctl",
	})
	for _, test := range tests {
		f := JournalCtlSource{}
		err := f.ConfigureByDSN(test.dsn, map[string]string{"type": "testtype"}, subLogger, "")
		cstest.AssertErrorContains(t, err, test.expectedErr)
	}
}

func TestOneShot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on windows")
	}
	tests := []struct {
		config         string
		expectedErr    string
		expectedOutput string
		expectedLines  int
		logLevel       log.Level
	}{
		{
			config: `
source: journalctl
mode: cat
journalctl_filter:
 - "-_UID=42"`,
			expectedErr:    "",
			expectedOutput: "journalctl: invalid option",
			logLevel:       log.WarnLevel,
			expectedLines:  0,
		},
		{
			config: `
source: journalctl
mode: cat
journalctl_filter:
 - _SYSTEMD_UNIT=ssh.service`,
			expectedErr:    "",
			expectedOutput: "",
			logLevel:       log.WarnLevel,
			expectedLines:  14,
		},
	}
	for _, ts := range tests {
		var logger *log.Logger
		var subLogger *log.Entry
		var hook *test.Hook
		if ts.expectedOutput != "" {
			logger, hook = test.NewNullLogger()
			logger.SetLevel(ts.logLevel)
			subLogger = logger.WithFields(log.Fields{
				"type": "journalctl",
			})
		} else {
			subLogger = log.WithFields(log.Fields{
				"type": "journalctl",
			})
		}
		tomb := tomb.Tomb{}
		out := make(chan types.Event, 100)
		j := JournalCtlSource{}
		err := j.Configure([]byte(ts.config), subLogger)
		if err != nil {
			t.Fatalf("Unexpected error : %s", err)
		}
		err = j.OneShotAcquisition(out, &tomb)
		cstest.AssertErrorContains(t, err, ts.expectedErr)
		if err != nil {
			continue
		}

		if ts.expectedLines != 0 {
			assert.Equal(t, ts.expectedLines, len(out))
		}

		if ts.expectedOutput != "" {
			if hook.LastEntry() == nil {
				t.Fatalf("Expected log output '%s' but got nothing !", ts.expectedOutput)
			}
			assert.Contains(t, hook.LastEntry().Message, ts.expectedOutput)
			hook.Reset()
		}
	}
}

func TestStreaming(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on windows")
	}
	tests := []struct {
		config         string
		expectedErr    string
		expectedOutput string
		expectedLines  int
		logLevel       log.Level
	}{
		{
			config: `
source: journalctl
mode: cat
journalctl_filter:
 - _SYSTEMD_UNIT=ssh.service`,
			expectedErr:    "",
			expectedOutput: "",
			logLevel:       log.WarnLevel,
			expectedLines:  14,
		},
	}
	for _, ts := range tests {
		var logger *log.Logger
		var subLogger *log.Entry
		var hook *test.Hook
		if ts.expectedOutput != "" {
			logger, hook = test.NewNullLogger()
			logger.SetLevel(ts.logLevel)
			subLogger = logger.WithFields(log.Fields{
				"type": "journalctl",
			})
		} else {
			subLogger = log.WithFields(log.Fields{
				"type": "journalctl",
			})
		}
		tomb := tomb.Tomb{}
		out := make(chan types.Event)
		j := JournalCtlSource{}
		err := j.Configure([]byte(ts.config), subLogger)
		if err != nil {
			t.Fatalf("Unexpected error : %s", err)
		}
		actualLines := 0
		if ts.expectedLines != 0 {
			go func() {
			READLOOP:
				for {
					select {
					case <-out:
						actualLines++
					case <-time.After(1 * time.Second):
						break READLOOP
					}
				}
			}()
		}

		err = j.StreamingAcquisition(out, &tomb)
		cstest.AssertErrorContains(t, err, ts.expectedErr)
		if err != nil {
			continue
		}

		if ts.expectedLines != 0 {
			time.Sleep(1 * time.Second)
			assert.Equal(t, ts.expectedLines, actualLines)
		}
		tomb.Kill(nil)
		tomb.Wait()
		output, _ := exec.Command("pgrep", "-x", "journalctl").CombinedOutput()
		if string(output) != "" {
			t.Fatalf("Found a journalctl process after killing the tomb !")
		}
		if ts.expectedOutput != "" {
			if hook.LastEntry() == nil {
				t.Fatalf("Expected log output '%s' but got nothing !", ts.expectedOutput)
			}
			assert.Contains(t, hook.LastEntry().Message, ts.expectedOutput)
			hook.Reset()
		}
	}
}

func TestMain(m *testing.M) {
	if os.Getenv("USE_SYSTEM_JOURNALCTL") == "" {
		currentDir, _ := os.Getwd()
		fullPath := filepath.Join(currentDir, "test_files")
		os.Setenv("PATH", fullPath+":"+os.Getenv("PATH"))
	}
	os.Exit(m.Run())
}
