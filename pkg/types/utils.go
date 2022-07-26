package types

import (
	"bufio"
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

func SetDefaultLoggerConfig(cfgMode string, cfgFolder string, cfgLevel log.Level, maxSize int, maxFiles int, maxAge int, compress *bool, forceColors bool) error {

	/*Configure logs*/
	if cfgMode == "file" {
		_maxsize := 500
		if maxSize != 0 {
			_maxsize = maxSize
		}
		_maxfiles := 3
		if maxFiles != 0 {
			_maxfiles = maxFiles
		}
		_maxage := 28
		if maxAge != 0 {
			_maxage = maxAge
		}
		_compress := true
		if compress != nil {
			_compress = *compress
		}
		/*cf. https://github.com/natefinch/lumberjack/issues/82
		let's create the file beforehand w/ the right perms */
		fname := cfgFolder + "/crowdsec.log"
		// check if file exists
		_, err := os.Stat(fname)
		// create file if not exists, purposefully ignore errors
		if os.IsNotExist(err) {
			file, _ := os.OpenFile(fname, os.O_RDWR|os.O_CREATE, 0600)
			file.Close()
		}

		LogOutput = &lumberjack.Logger{
			Filename:   fname,
			MaxSize:    _maxsize,
			MaxBackups: _maxfiles,
			MaxAge:     _maxage,
			Compress:   _compress,
		}
		log.SetOutput(LogOutput)
	} else if cfgMode != "stdout" {
		return fmt.Errorf("log mode '%s' unknown", cfgMode)
	}
	logLevel = cfgLevel
	log.SetLevel(logLevel)
	logFormatter = &log.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true, ForceColors: forceColors}
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
	tmpfile, err := ioutil.TempFile("", "crowdsec-crash.*.txt")
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

func IntPtr(i int) *int {
	return &i
}

func Int32Ptr(i int32) *int32 {
	return &i
}

func BoolPtr(b bool) *bool {
	return &b
}

func InSlice(str string, slice []string) bool {
	for _, item := range slice {
		if str == item {
			return true
		}
	}
	return false
}

func UtcNow() time.Time {
	return time.Now().UTC()
}

func GetLineCountForFile(filepath string) int {
	f, err := os.Open(filepath)
	if err != nil {
		log.Fatalf("unable to open log file %s : %s", filepath, err)
	}
	defer f.Close()
	lc := 0
	fs := bufio.NewScanner(f)
	for fs.Scan() {
		lc++
	}
	return lc
}
