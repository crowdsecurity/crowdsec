package trace

import (
	"fmt"
	"os"
	"runtime/debug"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/pkg/version"
)

func WriteStackTrace(iErr interface{}) string {
	tmpfile, err := os.CreateTemp("", "crowdsec-crash.*.txt")
	if err != nil {
		log.Fatal(err)
	}
	if _, err := tmpfile.Write([]byte(fmt.Sprintf("error : %+v\n", iErr))); err != nil {
		tmpfile.Close()
		log.Fatal(err)
	}
	if _, err := tmpfile.Write([]byte(version.FullString())); err != nil {
		tmpfile.Close()
		log.Fatal(err)
	}
	if _, err := tmpfile.Write(debug.Stack()); err != nil {
		tmpfile.Close()
		log.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		log.Fatal(err)
	}
	return tmpfile.Name()
}

//CatchPanic is a util func that we should call from all go-routines to ensure proper stacktrace handling
func CatchPanic(component string) {
	if r := recover(); r != nil {
		log.Errorf("crowdsec - goroutine %s crashed : %s", component, r)
		log.Errorf("please report this error to https://github.com/crowdsecurity/crowdsec/")
		filename := WriteStackTrace(r)
		log.Errorf("stacktrace/report is written to %s : please join it to your issue", filename)
		log.Fatalf("crowdsec stopped")
	}
}
