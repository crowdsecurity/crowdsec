package trace

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/version"
)

//
// Public API, using a singleton for simpler API & backwards compatibility
//

// Init is called after reading the configuration to set a persistent location.
// (i.e. config_paths.data_dir should be persistent even within containers)
// If not called, the default is /tmp or equivalent
func Init(dir string) {
	keeper.dir = dir
}

// CatchPanic should be called from all go-routines to ensure proper stack trace reporting
func CatchPanic(component string) {
	keeper.catchPanic(component)
}

// WriteStackTrace writes a stack trace to a file and returns the path
func WriteStackTrace(iErr any) (string, error) {
	return keeper.writeStackTrace(iErr)
}

// List returns a list of all collected files
func List() ([]string, error) {
	return keeper.list()
}

type traceKeeper struct {
	mutex         *sync.Mutex   // serialize access to the trace directory
	dir           string        // where stack traces are dumped
	crashFileGlob string        // pattern to create or match files
	removeAfter   time.Duration // how long to keep files
	keepMaxFiles  int           // delete oldest files if there are more than this
}

var keeper = &traceKeeper{
	mutex:         &sync.Mutex{},
	dir:           os.TempDir(),
	crashFileGlob: "crowdsec-crash.*.txt",
	removeAfter:   30 * 24 * time.Hour,
	keepMaxFiles:  100,
}

func (tk *traceKeeper) list() ([]string, error) {
	files, err := filepath.Glob(filepath.Join(tk.dir, tk.crashFileGlob))
	if err != nil {
		return nil, err
	}

	return files, nil
}

func (tk *traceKeeper) purge() {
	// Run in a mutex in case of concurrent, recoverable panics from apiserver
	tk.mutex.Lock()
	defer tk.mutex.Unlock()

	files, err := tk.list()
	if err != nil {
		log.Errorf("error listing crash files for cleanup: %s", err)
		return
	}

	// Sort files by modification time, newest first
	sort.Slice(files, func(i, j int) bool {
		fi, err := os.Stat(files[i])
		if err != nil {
			return true
		}

		fj, err := os.Stat(files[j])
		if err != nil {
			return false
		}

		return fi.ModTime().After(fj.ModTime())
	})

	now := time.Now()
	kept := 0

	for _, file := range files {
		if kept >= tk.keepMaxFiles {
			log.Infof("Removing excess trace file: %s", file)

			if err := os.Remove(file); err != nil {
				log.Errorf("error removing old crash file %s: %s", file, err)
			}

			continue
		}

		fi, err := os.Stat(file)
		if err != nil {
			log.Errorf("error stating file %s: %s", file, err)
			continue
		}

		if now.Sub(fi.ModTime()) > tk.removeAfter {
			log.Infof("Removing excess trace file: %s", file)

			if err := os.Remove(file); err != nil {
				log.Errorf("error removing old crash file %s: %s", file, err)
			}

			continue
		}

		kept++
	}
}

func (tk *traceKeeper) writeStackTrace(iErr any) (string, error) {
	tk.purge()

	tmpfile, err := os.CreateTemp(tk.dir, tk.crashFileGlob)
	if err != nil {
		return "", err
	}
	defer tmpfile.Close()

	if _, err := fmt.Fprintf(tmpfile, "error: %+v\n", iErr); err != nil {
		return "", err
	}

	if _, err := tmpfile.WriteString(version.FullString()); err != nil {
		return "", err
	}

	if _, err := tmpfile.Write(debug.Stack()); err != nil {
		return "", err
	}

	return tmpfile.Name(), nil
}

func (tk *traceKeeper) catchPanic(component string) {
	r := recover()
	if r == nil {
		return
	}

	log.Errorf("crowdsec - goroutine %s crashed: %s", component, r)
	log.Error("please report this error to https://github.com/crowdsecurity/crowdsec/issues")

	filename, err := tk.writeStackTrace(r)
	if err != nil {
		log.Errorf("unable to write stacktrace: %s", err)
	}

	log.Errorf("stacktrace/report is written to %s: please join it to your issue", filename)
	log.Fatal("crowdsec stopped")
}
