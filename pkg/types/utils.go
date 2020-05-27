package types

import (
	"encoding/binary"
	"fmt"
	"net"

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

var logMode string
var logFolder string
var logLevel log.Level

func SetDefaultLoggerConfig(inlogMode string, inlogFolder string, inlogLevel log.Level) error {
	logMode = inlogMode
	logFolder = inlogFolder
	logLevel = inlogLevel

	/*Configure logs*/
	if logMode == "file" {
		log.SetOutput(&lumberjack.Logger{
			Filename:   logFolder + "/crowdsec.log",
			MaxSize:    500, //megabytes
			MaxBackups: 3,
			MaxAge:     28,   //days
			Compress:   true, //disabled by default
		})
		log.SetFormatter(&log.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true})
	} else if logMode != "stdout" {
		return fmt.Errorf("log mode '%s' unknown", logMode)
	}
	log.SetLevel(logLevel)
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
	if logLevel >= log.InfoLevel {
		log.SetFormatter(&log.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true})
	}
	if logLevel >= log.DebugLevel {
		log.SetReportCaller(true)
	}
	return nil
}

func ConfigureLogger(clog *log.Logger) error {
	/*Configure logs*/
	if logMode == "file" {
		clog.SetOutput(&lumberjack.Logger{
			Filename:   logFolder + "/crowdsec.log",
			MaxSize:    500, //megabytes
			MaxBackups: 3,
			MaxAge:     28,   //days
			Compress:   true, //disabled by default
		})
		clog.SetFormatter(&log.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true})
	} else if logMode != "stdout" {
		return fmt.Errorf("log mode '%s' unknown", logMode)
	}
	clog.SetLevel(logLevel)
	clog.SetFormatter(&log.TextFormatter{FullTimestamp: true})
	if logLevel >= log.InfoLevel {
		clog.SetFormatter(&log.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true})
	}
	if logLevel >= log.DebugLevel {
		clog.SetReportCaller(true)
	}
	return nil
}
