//
// Copyright (c) 2016-2017 Konstanin Ivanov <kostyarin.ivanov@gmail.com>.
// All rights reserved. This program is free software. It comes without
// any warranty, to the extent permitted by applicable law. You can
// redistribute it and/or modify it under the terms of the Do What
// The Fuck You Want To Public License, Version 2, as published by
// Sam Hocevar. See LICENSE file for more details or see below.
//

//
//        DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.
//

package grok

import (
	"testing"
)

func TestHost_Must(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("missing panic")
		}
	}()
	h := New()
	h.Must("", "")
}

func TestNewBase(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("NewBase panics: %v", r)
		}
	}()
	h := NewBase()
	_ = h
}

//
// TODO/REDO ah-ha-ha
//

/*
func testPattern(t *testing.T, name string,
	input string, expect map[string]string) {
	h := NewBase()
	p, err := h.Get(name)
	if err != nil {
		t.Error(err)
		return
	}
	if !mssTest(expect, p.Parse(input)) {
		t.Errorf("pattern [%s] missmatches\n%v\n%v\n%v", name,
			p.Parse(input),
			expect,
			p)
	}
}

func Test_basePatterns_base(t *testing.T) {
	testPattern(t, "USERNAME",
		"jho.blow-motherfucker666",
		map[string]string{
			"USERNAME": "jho.blow-motherfucker666",
		})
	testPattern(t, "USER",
		"jho.blow-motherfucker666",
		map[string]string{
			"USERNAME": "jho.blow-motherfucker666",
			"USER":     "jho.blow-motherfucker666",
		})
	// TODO
	// --testPattern(t, "EMAILLOCALPART", `[a-zA-Z][a-zA-Z0-9_.+-=:]+`)
	// --testPattern(t, "HOSTNAME", `\b[0-9A-Za-z][0-9A-Za-z-]{0,62}(?:\.[0-9A-Za-z][0-9A-Za-z-]{0,62})*(\.?|\b)`)
	// --testPattern(t, "EMAILADDRESS", `%{EMAILLOCALPART}@%{HOSTNAME}`)
	// --testPattern(t, "HTTPDUSER", `%{EMAILADDRESS}|%{USER}`)
	// --testPattern(t, "INT", `[+-]?(?:[0-9]+)`)
	// --testPattern(t, "BASE10NUM", `[+-]?(?:(?:[0-9]+(?:\.[0-9]+)?)|(?:\.[0-9]+))`)
	// --testPattern(t, "NUMBER", `%{BASE10NUM}`)
	// --testPattern(t, "BASE16NUM", `[+-]?(?:0x)?(?:[0-9A-Fa-f]+)`)
	// --testPattern(t, "BASE16FLOAT", `\b[+-]?(?:0x)?(?:(?:[0-9A-Fa-f]+(?:\.[0-9A-Fa-f]*)?)|(?:\.[0-9A-Fa-f]+))\b`)
}

func Test_basePatterns_wordsNumbers(t *testing.T) {
	// TODO
	testPattern(t, "POSINT",
		"19",
		map[string]string{
			"POSINT": "19",
		})
	testPattern(t, "NONNEGINT",
		"0",
		map[string]string{
			"NONNEGINT": "0",
		})
	testPattern(t, "WORD",
		"word",
		map[string]string{
			"WORD": "word",
		})
	// --testPattern(t, "NOTSPACE", `\S+`)
	// --testPattern(t, "SPACE", `\s*`)
	// --testPattern(t, "DATA", `.*?`)
	// --testPattern(t, "GREEDYDATA", `.*`)
	// --testPattern(t, "QUOTEDSTRING", `("(\\.|[^\\"]+)+")|""|('(\\.|[^\\']+)+')|''|`+"(`(\\\\.|[^\\\\`]+)+`)|``")
	// --testPattern(t, "UUID", `[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}`)
}

func Test_basePatterns_networking(t *testing.T) {
	// TODO
	// Networking
	// --testPattern(t, "CISCOMAC", `(?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4}`)
	// --testPattern(t, "WINDOWSMAC", `(?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2}`)
	// --testPattern(t, "COMMONMAC", `(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}`)
	// --testPattern(t, "MAC", `%{CISCOMAC}|%{WINDOWSMAC}|%{COMMONMAC}`)
	// --testPattern(t, "IPV6", `((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?`)
	// --testPattern(t, "IPV4", `(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))`)
	// --testPattern(t, "IP", `%{IPV6}|%{IPV4}`)
	// --testPattern(t, "IPORHOST", `%{IP}|%{HOSTNAME}`)
	// --testPattern(t, "HOSTPORT", `%{IPORHOST}:%{POSINT}`)
}

func Test_basePatterns_paths(t *testing.T) {
	// TODO
	// paths
	// --testPattern(t, "UNIXPATH", `(/([\w_%!$@:.,~-]+|\\.)*)+`)
	// --testPattern(t, "TTY", `/dev/(pts|tty([pq])?)(\w+)?/?(?:[0-9]+)`)
	// --testPattern(t, "WINPATH", `(?:[A-Za-z]+:|\\)(?:\\[^\\?*]*)+`)
	// --testPattern(t, "PATH", `%{UNIXPATH}|%{WINPATH}`)
	// --testPattern(t, "URIPROTO", `[A-Za-z]+(\+[A-Za-z+]+)?`)
	// --testPattern(t, "URIHOST", `%{IPORHOST}(?::%{POSINT:port})?`)
}

func Test_basePatterns_uri(t *testing.T) {
	// TODO
	// uripath comes loosely from RFC1738, but mostly from what Firefox
	// doesn't turn into %XX
	// --testPattern(t, "URIPATH", `(?:/[A-Za-z0-9$.+!*'(){},~:;=@#%_\-]*)+`)
	// --testPattern(t, "URIPARAM", `\?[A-Za-z0-9$.+!*'|(){},~@#%&/=:;_?\-\[\]<>]*`)
	// --testPattern(t, "URIPATHPARAM", `%{URIPATH}(?:%{URIPARAM})?`)
	// --testPattern(t, "URI", `%{URIPROTO}://(?:%{USER}(?::[^@]*)?@)?(?:%{URIHOST})?(?:%{URIPATHPARAM})?`)
}

func Test_basePatterns_date(t *testing.T) {
	// TODO
	// Months: January, Feb, 3, 03, 12, December
	// --testPattern(t, "MONTH", `\bJan(?:uary|uar)?|Feb(?:ruary|ruar)?|M(?:a|ä)?r(?:ch|z)?|Apr(?:il)?|Ma(?:y|i)?|Jun(?:e|i)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|O(?:c|k)?t(?:ober)?|Nov(?:ember)?|De(?:c|z)(?:ember)?\b`)
	// --testPattern(t, "MONTHNUM", `0?[1-9]|1[0-2]`)
	testPattern(t, "MONTHNUM2",
		"11",
		map[string]string{
			"MONTHNUM2": "11",
		})
	// --testPattern(t, "MONTHDAY", `(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9]`)
	// Days: Monday, Tue, Thu, etc...
	// --testPattern(t, "DAY", `Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|Sat(?:urday)?|Sun(?:day)?`)
}

func Test_basePatterns_time(t *testing.T) {
	// Years?
	// --testPattern(t, "YEAR", `(?:\d\d){1,2}`)
	// --testPattern(t, "HOUR", `2[0123]|[01]?[0-9]`)
	// --testPattern(t, "MINUTE", `[0-5][0-9]`)
	// '60' is a leap second in most time standards and thus is valid.
	// --testPattern(t, "SECOND", `(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?`)
	// --testPattern(t, "TIME", `%{HOUR}:%{MINUTE}:%{SECOND}`)
}

func Test_basePatterns_timestamps(t *testing.T) {
	// datestamp is YYYY/MM/DD-HH:MM:SS.UUUU (or something like it)
	// --testPattern(t, "DATE_US", `%{MONTHNUM}[/-]%{MONTHDAY}[/-]%{YEAR}`)
	// --testPattern(t, "DATE_EU", `%{MONTHDAY}[./-]%{MONTHNUM}[./-]%{YEAR}`)
	// I really don't know how it's called
	// --testPattern(t, "DATE_X", `%{YEAR}/%{MONTHNUM2}/%{MONTHDAY}`)
	// --testPattern(t, "ISO8601_TIMEZONE", `Z|[+-]%{HOUR}(?::?%{MINUTE})`)
	// --testPattern(t, "ISO8601_SECOND", `%{SECOND}|60`)
	// --testPattern(t, "TIMESTAMP_ISO8601", `%{YEAR}-%{MONTHNUM}-%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::?%{SECOND})?%{ISO8601_TIMEZONE}?`)
	// --testPattern(t, "DATE", `%{DATE_US}|%{DATE_EU}|%{DATE_X}`)
	// --testPattern(t, "DATESTAMP", `%{DATE}[- ]%{TIME}`)
	// --testPattern(t, "TZ", `[A-Z]{3}`)
	// --testPattern(t, "NUMTZ", `[+-]\d{4}`)
	// --testPattern(t, "DATESTAMP_RFC822", `%{DAY} %{MONTH} %{MONTHDAY} %{YEAR} %{TIME} %{TZ}`)
	// --testPattern(t, "DATESTAMP_RFC2822", `%{DAY}, %{MONTHDAY} %{MONTH} %{YEAR} %{TIME} %{ISO8601_TIMEZONE}`)
	// --testPattern(t, "DATESTAMP_OTHER", `%{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{TZ} %{YEAR}`)
	// --testPattern(t, "DATESTAMP_EVENTLOG", `%{YEAR}%{MONTHNUM2}%{MONTHDAY}%{HOUR}%{MINUTE}%{SECOND}`)
	// --testPattern(t, "HTTPDERROR_DATE", `%{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{YEAR}`)
}

func Test_basePatterns_golangTime(t *testing.T) {
	// golang time patterns
	// --testPattern(t, "ANSIC", `%{DAY} %{MONTH} [_123]\d %{TIME} %{YEAR}"`)
	// --testPattern(t, "UNIXDATE", `%{DAY} %{MONTH} [_123]\d %{TIME} %{TZ} %{YEAR}`)
	// --testPattern(t, "RUBYDATE", `%{DAY} %{MONTH} [0-3]\d %{TIME} %{NUMTZ} %{YEAR}`)
	// --testPattern(t, "RFC822Z", `[0-3]\d %{MONTH} %{YEAR} %{TIME} %{NUMTZ}`)
	// --testPattern(t, "RFC850", `%{DAY}, [0-3]\d-%{MONTH}-%{YEAR} %{TIME} %{TZ}`)
	// --testPattern(t, "RFC1123", `%{DAY}, [0-3]\d %{MONTH} %{YEAR} %{TIME} %{TZ}`)
	// --testPattern(t, "RFC1123Z", `%{DAY}, [0-3]\d %{MONTH} %{YEAR} %{TIME} %{NUMTZ}`)
	// --testPattern(t, "RFC3339", `%{YEAR}-[01]\d-[0-3]\dT%{TIME}%{ISO8601_TIMEZONE}`)
	// --testPattern(t, "RFC3339NANO", `%{YEAR}-[01]\d-[0-3]\dT%{TIME}\.\d{9}%{ISO8601_TIMEZONE}`)
	// --testPattern(t, "KITCHEN", `\d{1,2}:\d{2}(AM|PM|am|pm)`)
}

func Test_basePatterns_syslogDates(t *testing.T) {
	// Syslog Dates: Month Day HH:MM:SS
	// --testPattern(t, "SYSLOGTIMESTAMP", `%{MONTH} +%{MONTHDAY} %{TIME}`)
	// --testPattern(t, "PROG", `[\x21-\x5a\x5c\x5e-\x7e]+`)
	// --testPattern(t, "SYSLOGPROG", `%{PROG:program}(?:\[%{POSINT:pid}\])?`)
	// --testPattern(t, "SYSLOGHOST", `%{IPORHOST}`)
	// --testPattern(t, "SYSLOGFACILITY", `<%{NONNEGINT:facility}.%{NONNEGINT:priority}>`)
	// --testPattern(t, "HTTPDATE", `%{MONTHDAY}/%{MONTH}/%{YEAR}:%{TIME} %{INT}`)
}

func Test_basePatterns_shortcuts(t *testing.T) {
	// Shortcuts
	// --testPattern(t, "QS", `%{QUOTEDSTRING}`)
}

func Test_basePatterns_logLevels(t *testing.T) {
	// Log Levels
	// --testPattern(t, "LOGLEVEL", `[Aa]lert|ALERT|[Tt]race|TRACE|[Dd]ebug|DEBUG|[Nn]otice|NOTICE|[Ii]nfo|INFO|[Ww]arn?(?:ing)?|WARN?(?:ING)?|[Ee]rr?(?:or)?|ERR?(?:OR)?|[Cc]rit?(?:ical)?|CRIT?(?:ICAL)?|[Ff]atal|FATAL|[Ss]evere|SEVERE|EMERG(?:ENCY)?|[Ee]merg(?:ency)?`)
}

func Test_basePatterns_logFormats(t *testing.T) {
	// Log formats
	// --testPattern(t, "SYSLOGBASE", `%{SYSLOGTIMESTAMP:timestamp} (?:%{SYSLOGFACILITY} )?%{SYSLOGHOST:logsource} %{SYSLOGPROG}:`)
	// --testPattern(t, "COMMONAPACHELOG", `%{IPORHOST:clientip} %{HTTPDUSER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%{NUMBER:bytes}|-)`)
	// --testPattern(t, "COMBINEDAPACHELOG", `%{COMMONAPACHELOG} %{QS:referrer} %{QS:agent}`)
	// --testPattern(t, "HTTPD20_ERRORLOG", `\[%{HTTPDERROR_DATE:timestamp}\] \[%{LOGLEVEL:loglevel}\] (?:\[client %{IPORHOST:clientip}\] ){0,1}%{GREEDYDATA:errormsg}`)
	// --testPattern(t, "HTTPD24_ERRORLOG", `\[%{HTTPDERROR_DATE:timestamp}\] \[%{WORD:module}:%{LOGLEVEL:loglevel}\] \[pid %{POSINT:pid}:tid %{NUMBER:tid}\]( \(%{POSINT:proxy_errorcode}\)%{DATA:proxy_errormessage}:)?( \[client %{IPORHOST:client}:%{POSINT:clientport}\])? %{DATA:errorcode}: %{GREEDYDATA:message}`)
	// --testPattern(t, "HTTPD_ERRORLOG", `%{HTTPD20_ERRORLOG}|%{HTTPD24_ERRORLOG}`)
}
*/
