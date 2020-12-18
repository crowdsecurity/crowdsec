package types

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

func IP2Int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func Int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

//Stolen from : https://github.com/llimllib/ipaddress/
// Return the final address of a net range. Convert to IPv4 if possible,
// otherwise return an ipv6
func LastAddress(n *net.IPNet) net.IP {
	ip := n.IP.To4()
	if ip == nil {
		ip = n.IP
		return net.IP{
			ip[0] | ^n.Mask[0], ip[1] | ^n.Mask[1], ip[2] | ^n.Mask[2],
			ip[3] | ^n.Mask[3], ip[4] | ^n.Mask[4], ip[5] | ^n.Mask[5],
			ip[6] | ^n.Mask[6], ip[7] | ^n.Mask[7], ip[8] | ^n.Mask[8],
			ip[9] | ^n.Mask[9], ip[10] | ^n.Mask[10], ip[11] | ^n.Mask[11],
			ip[12] | ^n.Mask[12], ip[13] | ^n.Mask[13], ip[14] | ^n.Mask[14],
			ip[15] | ^n.Mask[15]}
	}

	return net.IPv4(
		ip[0]|^n.Mask[0],
		ip[1]|^n.Mask[1],
		ip[2]|^n.Mask[2],
		ip[3]|^n.Mask[3])
}

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
	if logLevel >= log.InfoLevel {
		logFormatter = &log.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true}
		log.SetFormatter(logFormatter)
	}

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

//CatchPanic is a util func that we should call from all go-routines to ensure proper stacktrace handling
func CatchPanic(component string) {

	if r := recover(); r != nil {

		/*mimic gin's behaviour on broken pipe*/
		var brokenPipe bool
		if ne, ok := r.(*net.OpError); ok {
			if se, ok := ne.Err.(*os.SyscallError); ok {
				if se.Err == syscall.EPIPE || se.Err == syscall.ECONNRESET {
					brokenPipe = true
				}
			}
		}

		tmpfile, err := ioutil.TempFile("/tmp/", "crowdsec-crash.*.txt")
		if err != nil {
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

		log.Errorf("crowdsec - goroutine %s crashed : %s", component, r)
		log.Errorf("please report this error to https://github.com/crowdsecurity/crowdsec/")
		log.Errorf("stacktrace/report is written to %s : please join it to your issue", tmpfile.Name())

		/*if it's not a broken pipe error, we don't want to fatal. it can happen from Local API pov*/
		if !brokenPipe {
			log.Fatalf("crowdsec stopped")
		}

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
