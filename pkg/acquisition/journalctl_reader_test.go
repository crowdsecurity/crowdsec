package acquisition

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	tomb "gopkg.in/tomb.v2"
)

/*
 As we can't decently run journalctl in the CI but we still need to test the command execution aspect :
  - we create tests 'output only' (cf. TestSimJournalctlCat) that just produce outputs
  - we run ourselves (os.Args[0]) with specific args to call specific 'output only' tests
  - and this is how we test the behavior
*/

//14 lines of sshd logs
var testjournalctl_output_1 string = `-- Logs begin at Fri 2019-07-26 17:13:13 CEST, end at Mon 2020-11-23 09:17:34 CET. --
Nov 22 11:22:19 zeroed sshd[1480]: Invalid user wqeqwe from 127.0.0.1 port 55818
Nov 22 11:22:23 zeroed sshd[1480]: Failed password for invalid user wqeqwe from 127.0.0.1 port 55818 ssh2
Nov 22 11:23:22 zeroed sshd[1769]: Invalid user wqeqwe1 from 127.0.0.1 port 55824
Nov 22 11:23:24 zeroed sshd[1769]: Disconnecting invalid user wqeqwe1 127.0.0.1 port 55824: Too many authentication failures [preauth]
Nov 22 11:23:24 zeroed sshd[1777]: Invalid user wqeqwe2 from 127.0.0.1 port 55826
Nov 22 11:23:25 zeroed sshd[1777]: Disconnecting invalid user wqeqwe2 127.0.0.1 port 55826: Too many authentication failures [preauth]
Nov 22 11:23:25 zeroed sshd[1780]: Invalid user wqeqwe3 from 127.0.0.1 port 55828
Nov 22 11:23:26 zeroed sshd[1780]: Disconnecting invalid user wqeqwe3 127.0.0.1 port 55828: Too many authentication failures [preauth]
Nov 22 11:23:26 zeroed sshd[1786]: Invalid user wqeqwe4 from 127.0.0.1 port 55830
Nov 22 11:23:27 zeroed sshd[1786]: Failed password for invalid user wqeqwe4 from 127.0.0.1 port 55830 ssh2
Nov 22 11:23:27 zeroed sshd[1786]: Disconnecting invalid user wqeqwe4 127.0.0.1 port 55830: Too many authentication failures [preauth]
Nov 22 11:23:27 zeroed sshd[1791]: Invalid user wqeqwe5 from 127.0.0.1 port 55834
Nov 22 11:23:27 zeroed sshd[1791]: Failed password for invalid user wqeqwe5 from 127.0.0.1 port 55834 ssh2
`

func TestSimJournalctlCat(t *testing.T) {
	if os.Getenv("GO_WANT_TEST_OUTPUT") != "1" {
		return
	}
	defer os.Exit(0)
	fmt.Printf(testjournalctl_output_1)
}

func TestSimJournalctlCatError(t *testing.T) {
	if os.Getenv("GO_WANT_TEST_OUTPUT") != "1" {
		return
	}
	defer os.Exit(0)
	fmt.Printf("this is a single line being produced")
	log.Warningf("this is an error message")
}

func TestSimJournalctlCatOneLine(t *testing.T) {
	if os.Getenv("GO_WANT_TEST_OUTPUT") != "1" {
		return
	}
	defer os.Exit(0)
	fmt.Printf("this is a single line being produced")
}

func TestJournaldTail(t *testing.T) {
	tests := []struct {
		cfg          DataSourceCfg
		config_error string
		read_error   string
		tomb_error   string
		lines        int
	}{
		{ //missing filename(s)
			cfg: DataSourceCfg{
				Mode: TAIL_MODE,
			},
			config_error: "journalctl_filter shouldn't be empty",
		},
		{ //bad mode
			cfg: DataSourceCfg{
				Mode:              "ratatata",
				JournalctlFilters: []string{"-test.run=DoesNotExist", "--"},
			},
			/*here would actually be the journalctl error message on bad args, but you get the point*/
			config_error: "unknown mode 'ratatata' for journald source",
		},
		{ //wrong arguments
			cfg: DataSourceCfg{
				Mode:              TAIL_MODE,
				JournalctlFilters: []string{"--this-is-bad-option", "--"},
			},
			/*here would actually be the journalctl error message on bad args, but you get the point*/
			tomb_error: "flag provided but not defined: -this-is-bad-option",
		},
	}

	//we're actually using tests to do this, hold my beer and watch this
	JOURNALD_CMD = os.Args[0]
	JOURNALD_DEFAULT_TAIL_ARGS = []string{}

	for tidx, test := range tests {
		journalSrc := new(JournaldSource)
		err := journalSrc.Configure(test.cfg)
		if test.config_error != "" {
			assert.Contains(t, fmt.Sprintf("%s", err), test.config_error)
			log.Infof("expected config error ok : %s", test.config_error)
			continue
		} else {
			if err != nil {
				t.Fatalf("%d/%d unexpected config error %s", tidx, len(tests), err)
			}
		}

		assert.Equal(t, journalSrc.Mode(), test.cfg.Mode)

		//this tells our fake tests to produce data
		journalSrc.Cmd.Env = []string{"GO_WANT_TEST_OUTPUT=1"}

		out := make(chan types.Event)
		tomb := tomb.Tomb{}
		count := 0

		//start consuming the data before we start the prog, so that chan isn't full
		go func() {
			for {
				select {
				case <-out:
					count++
				case <-time.After(1 * time.Second):
					return
				}
			}
		}()

		err = journalSrc.StartReading(out, &tomb)
		if test.read_error != "" {
			assert.Contains(t, fmt.Sprintf("%s", err), test.read_error)
			log.Infof("expected read error ok : %s", test.read_error)
			continue
		} else {
			if err != nil {
				t.Fatalf("%d/%d unexpected read error %s", tidx, len(tests), err)
			}
		}

		time.Sleep(2 * time.Second)
		log.Printf("now let's check number of lines & errors")
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

func TestJournaldSimple(t *testing.T) {
	JOURNALD_CMD = os.Args[0]
	JOURNALD_DEFAULT_TAIL_ARGS = []string{}
	jBaseCfg := DataSourceCfg{
		JournalctlFilters: []string{"-test.run=TestSimJournalctlCat", "--"},
		Mode:              CAT_MODE,
	}

	journalSrc := new(JournaldSource)
	err := journalSrc.Configure(jBaseCfg)
	if err != nil {
		t.Fatalf("configuring journalctl : %s", err)
	}
	journalSrc.Cmd.Env = []string{"GO_WANT_TEST_OUTPUT=1"}

	out := make(chan types.Event)
	tomb := tomb.Tomb{}
	count := 0

	//start the reading : it doesn't give hand back before it's done
	err = journalSrc.StartReading(out, &tomb)
	if err != nil {
		t.Fatalf("unexpected read error %s", err)
	}

RLOOP:
	for {
		select {
		case <-out:
			count++
		case <-time.After(1 * time.Second):
			break RLOOP
		}
	}
	//we expect 14 lines to be read
	assert.Equal(t, 14, count)

}

func TestJournalctlKill(t *testing.T) {
	cfg := DataSourceCfg{
		Mode:              CAT_MODE,
		JournalctlFilters: []string{"-test.run=TestSimJournalctlCatOneLine", "--"},
	}
	//we're actually using tests to do this, hold my beer and watch this
	JOURNALD_CMD = os.Args[0]
	JOURNALD_DEFAULT_TAIL_ARGS = []string{}

	log.SetLevel(log.TraceLevel)
	journalSrc := new(JournaldSource)
	err := journalSrc.Configure(cfg)
	if err != nil {
		t.Fatalf("unexpected config error %s", err)
	}
	journalSrc.Cmd.Env = []string{"GO_WANT_TEST_OUTPUT=1"}

	out := make(chan types.Event)
	tb := tomb.Tomb{}

	err = journalSrc.StartReading(out, &tb)
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
