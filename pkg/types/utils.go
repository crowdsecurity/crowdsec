package types

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var logFormatter log.Formatter
var LogOutput *lumberjack.Logger //io.Writer
var logLevel log.Level

func SetDefaultLoggerConfig(cfgMode string, cfgFolder string, cfgLevel log.Level) error {

	/*Configure logs*/
	if cfgMode == "file" {
		LogOutput = &lumberjack.Logger{
			Filename:   cfgFolder + "/crowdsec.log",
			MaxSize:    500, //megabytes
			MaxBackups: 3,
			MaxAge:     28,   //days
			Compress:   true, //disabled by default
		}
		log.SetOutput(LogOutput)
	} else if cfgMode != "stdout" {
		return fmt.Errorf("log mode '%s' unknown", cfgMode)
	}
	logLevel = cfgLevel
	log.SetLevel(logLevel)
	logFormatter = &log.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true}
	log.SetFormatter(logFormatter)
	return nil
}

func ConfigureLogger(clog *log.Logger) error {
	/*Configure logs*/
	if LogOutput != nil {
		clog.SetOutput(LogOutput)
	}

	if logFormatter != nil {
		clog.SetFormatter(logFormatter)
	}
	clog.SetLevel(logLevel)
	return nil
}

func Clone(a, b interface{}) error {

	buff := new(bytes.Buffer)
	enc := gob.NewEncoder(buff)
	dec := gob.NewDecoder(buff)
	if err := enc.Encode(a); err != nil {
		return fmt.Errorf("failed cloning %T", a)
	}
	if err := dec.Decode(b); err != nil {
		return fmt.Errorf("failed cloning %T", b)
	}
	return nil
}

func WriteStackTrace(iErr interface{}) string {
	tmpfile, err := ioutil.TempFile("/tmp/", "crowdsec-crash.*.txt")
	if err != nil {
		log.Fatal(err)
	}
	if _, err := tmpfile.Write([]byte(fmt.Sprintf("error : %+v\n", iErr))); err != nil {
		tmpfile.Close()
		log.Fatal(err)
	}
	if _, err := tmpfile.Write([]byte(cwversion.ShowStr())); err != nil {
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

func ParseDuration(d string) (time.Duration, error) {
	durationStr := d
	if strings.HasSuffix(d, "d") {
		days := strings.Split(d, "d")[0]
		if len(days) == 0 {
			return 0, fmt.Errorf("'%s' can't be parsed as duration", d)
		}
		daysInt, err := strconv.Atoi(days)
		if err != nil {
			return 0, err
		}
		durationStr = strconv.Itoa(daysInt*24) + "h"
	}
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return 0, err
	}
	return duration, nil
}

/*help to copy the file, ioutil doesn't offer the feature*/

func copyFileContents(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return
	}
	err = out.Sync()
	return
}

/*copy the file, ioutile doesn't offer the feature*/
func CopyFile(sourceSymLink, destinationFile string) (err error) {

	sourceFile, err := filepath.EvalSymlinks(sourceSymLink)
	if err != nil {
		log.Infof("Not a symlink : %s", err)
		sourceFile = sourceSymLink
	}

	sourceFileStat, err := os.Stat(sourceFile)
	if err != nil {
		return
	}
	if !sourceFileStat.Mode().IsRegular() {
		// cannot copy non-regular files (e.g., directories,
		// symlinks, devices, etc.)
		return fmt.Errorf("copyFile: non-regular source file %s (%q)", sourceFileStat.Name(), sourceFileStat.Mode().String())
	}
	destinationFileStat, err := os.Stat(destinationFile)
	if err != nil {
		if !os.IsNotExist(err) {
			return
		}
	} else {
		if !(destinationFileStat.Mode().IsRegular()) {
			return fmt.Errorf("copyFile: non-regular destination file %s (%q)", destinationFileStat.Name(), destinationFileStat.Mode().String())
		}
		if os.SameFile(sourceFileStat, destinationFileStat) {
			return
		}
	}
	if err = os.Link(sourceFile, destinationFile); err == nil {
		return
	}
	err = copyFileContents(sourceFile, destinationFile)
	return
}

func StrPtr(s string) *string {
	return &s
}

func Int32Ptr(i int32) *int32 {
	return &i
}

func BoolPtr(b bool) *bool {
	return &b
}
