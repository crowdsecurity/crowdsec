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

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// Must is like Add but panics if the expression can't be parsed or
// the name is empty.
func (h Host) Must(name, expr string) {
	must(h.Add(name, expr))
}

// basePatterns is ordered: a pattern can only reference ones defined above it.
var basePatterns = []struct{ name, expr string }{
	//
	{"USERNAME", `[a-zA-Z0-9._-]+`},
	{"USER", `%{USERNAME}`},
	{"EMAILLOCALPART", `[a-zA-Z0-9_.+-=:]+`},
	{"HOSTNAME", `\b[0-9A-Za-z][0-9A-Za-z-]{0,62}(?:\.[0-9A-Za-z][0-9A-Za-z-]{0,62})*(\.?|\b)`},
	{"EMAILADDRESS", `%{EMAILLOCALPART}@%{HOSTNAME}`},
	{"HTTPDUSER", `%{EMAILADDRESS}|%{USER}`},
	{"INT", `[+-]?(?:[0-9]+)`},
	{"BASE10NUM", `[+-]?(?:(?:[0-9]+(?:\.[0-9]+)?)|(?:\.[0-9]+))`},
	{"NUMBER", `%{BASE10NUM}`},
	{"BASE16NUM", `[+-]?(?:0x)?(?:[0-9A-Fa-f]+)`},
	{"BASE16FLOAT", `\b[+-]?(?:0x)?(?:(?:[0-9A-Fa-f]+(?:\.[0-9A-Fa-f]*)?)|(?:\.[0-9A-Fa-f]+))\b`},
	//
	{"POSINT", `\b[1-9][0-9]*\b`},
	{"NONNEGINT", `\b[0-9]+\b`},
	{"WORD", `\b\w+\b`},
	{"NOTSPACE", `\S+`},
	{"SPACE", `\s*`},
	{"DATA", `.*?`},
	{"GREEDYDATA", `.*`},
	{"QUOTEDSTRING", `("(\\.|[^\\"]+)+")|""|('(\\.|[^\\']+)+')|''|` +
		"(`(\\\\.|[^\\\\`]+)+`)|``"},
	{"UUID", `[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}`},
	// Networking
	{"CISCOMAC", `(?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4}`},
	{"WINDOWSMAC", `(?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2}`},
	{"COMMONMAC", `(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}`},
	{"MAC", `%{CISCOMAC}|%{WINDOWSMAC}|%{COMMONMAC}`},
	{"IPV6", `((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?`}, //nolint:revive // regex literal
	{"IPV4", `(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)`},
	{"IP", `%{IPV6}|%{IPV4}`},
	{"IPORHOST", `%{IP}|%{HOSTNAME}`},
	{"HOSTPORT", `%{IPORHOST}:%{POSINT}`},

	// paths
	{"UNIXPATH", `(/([\w_%!$@:.,~-]+|\\.)*)+`},
	{"TTY", `/dev/(pts|tty([pq])?)(\w+)?/?(?:[0-9]+)`},
	{"WINPATH", `(?:[A-Za-z]+:|\\)(?:\\[^\\?*]*)+`},
	{"PATH", `%{UNIXPATH}|%{WINPATH}`},
	{"URIPROTO", `[A-Za-z]+(\+[A-Za-z+]+)?`},
	{"URIHOST", `%{IPORHOST}(?::%{POSINT:port})?`},
	// uripath comes loosely from RFC1738, but mostly from what Firefox
	// doesn't turn into %XX
	{"URIPATH", `(?:/[A-Za-z0-9$.+!*'(){},~:;=@#%_\-]*)+`},
	{"URIPARAM", `\?[A-Za-z0-9$.+!*'|(){},~@#%&/=:;_?\-\[\]<>]*`},
	{"URIPATHPARAM", `%{URIPATH}(?:%{URIPARAM})?`},
	{"URI", `%{URIPROTO}://(?:%{USER}(?::[^@]*)?@)?(?:%{URIHOST})?(?:%{URIPATHPARAM})?`},
	// Months: January, Feb, 3, 03, 12, December
	{"MONTH", `\bJan(?:uary|uar)?|Feb(?:ruary|ruar)?|M(?:a|ä)?r(?:ch|z)?|Apr(?:il)?|Ma(?:y|i)?|Jun(?:e|i)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|O(?:c|k)?t(?:ober)?|Nov(?:ember)?|De(?:c|z)(?:ember)?\b`},
	{"MONTHNUM", `0?[1-9]|1[0-2]`},
	{"MONTHNUM2", `0[1-9]|1[0-2]`},
	{"MONTHDAY", `(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9]`},
	// Days: Monday, Tue, Thu, etc...
	{"DAY", `Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|Sat(?:urday)?|Sun(?:day)?`},
	// Years?
	{"YEAR", `(?:\d\d){1,2}`},
	{"HOUR", `2[0123]|[01]?[0-9]`},
	{"MINUTE", `[0-5][0-9]`},
	// '60' is a leap second in most time standards and thus is valid.
	{"SECOND", `(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?`},
	{"TIME", `%{HOUR}:%{MINUTE}:%{SECOND}`},
	// datestamp is YYYY/MM/DD-HH:MM:SS.UUUU (or something like it)
	{"DATE_US", `%{MONTHNUM}[/-]%{MONTHDAY}[/-]%{YEAR}`},
	{"DATE_EU", `%{MONTHDAY}[./-]%{MONTHNUM}[./-]%{YEAR}`},
	// I really don't know how it's called
	{"DATE_X", `%{YEAR}/%{MONTHNUM2}/%{MONTHDAY}`},
	{"ISO8601_TIMEZONE", `Z|[+-]%{HOUR}(?::?%{MINUTE})`},
	{"ISO8601_SECOND", `%{SECOND}|60`},
	{"TIMESTAMP_ISO8601", `%{YEAR}-%{MONTHNUM}-%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::?%{SECOND})?%{ISO8601_TIMEZONE}?`},
	{"DATE", `%{DATE_US}|%{DATE_EU}|%{DATE_X}`},
	{"DATESTAMP", `%{DATE}[- ]%{TIME}`},
	{"TZ", `[A-Z]{3}`},
	{"NUMTZ", `[+-]\d{4}`},
	{"DATESTAMP_RFC822", `%{DAY} %{MONTH} %{MONTHDAY} %{YEAR} %{TIME} %{TZ}`},
	{"DATESTAMP_RFC2822", `%{DAY}, %{MONTHDAY} %{MONTH} %{YEAR} %{TIME} %{ISO8601_TIMEZONE}`},
	{"DATESTAMP_OTHER", `%{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{TZ} %{YEAR}`},
	{"DATESTAMP_EVENTLOG", `%{YEAR}%{MONTHNUM2}%{MONTHDAY}%{HOUR}%{MINUTE}%{SECOND}`},
	{"HTTPDERROR_DATE", `%{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{YEAR}`},
	// golang time patterns
	{"ANSIC", `%{DAY} %{MONTH} [_123]\d %{TIME} %{YEAR}"`},
	{"UNIXDATE", `%{DAY} %{MONTH} [_123]\d %{TIME} %{TZ} %{YEAR}`},
	{"RUBYDATE", `%{DAY} %{MONTH} [0-3]\d %{TIME} %{NUMTZ} %{YEAR}`},
	{"RFC822Z", `[0-3]\d %{MONTH} %{YEAR} %{TIME} %{NUMTZ}`},
	{"RFC850", `%{DAY}, [0-3]\d-%{MONTH}-%{YEAR} %{TIME} %{TZ}`},
	{"RFC1123", `%{DAY}, [0-3]\d %{MONTH} %{YEAR} %{TIME} %{TZ}`},
	{"RFC1123Z", `%{DAY}, [0-3]\d %{MONTH} %{YEAR} %{TIME} %{NUMTZ}`},
	{"RFC3339", `%{YEAR}-[01]\d-[0-3]\dT%{TIME}%{ISO8601_TIMEZONE}`},
	{"RFC3339NANO", `%{YEAR}-[01]\d-[0-3]\dT%{TIME}\.\d{9}%{ISO8601_TIMEZONE}`},
	{"KITCHEN", `\d{1,2}:\d{2}(AM|PM|am|pm)`},
	// Syslog Dates: Month Day HH:MM:SS
	{"SYSLOGTIMESTAMP", `%{MONTH} +%{MONTHDAY} %{TIME}`},
	{"PROG", `[\x21-\x5a\x5c\x5e-\x7e]+`},
	{"SYSLOGPROG", `%{PROG:program}(?:\[%{POSINT:pid}\])?`},
	{"SYSLOGHOST", `%{IPORHOST}`},
	{"SYSLOGFACILITY", `<%{NONNEGINT:facility}.%{NONNEGINT:priority}>`},
	{"HTTPDATE", `%{MONTHDAY}/%{MONTH}/%{YEAR}:%{TIME} %{INT}`},
	// Shortcuts
	{"QS", `%{QUOTEDSTRING}`},
	// Log Levels
	{"LOGLEVEL", `[Aa]lert|ALERT|[Tt]race|TRACE|[Dd]ebug|DEBUG|[Nn]otice|NOTICE|[Ii]nfo|INFO|[Ww]arn?(?:ing)?|WARN?(?:ING)?|[Ee]rr?(?:or)?|ERR?(?:OR)?|[Cc]rit?(?:ical)?|CRIT?(?:ICAL)?|[Ff]atal|FATAL|[Ss]evere|SEVERE|EMERG(?:ENCY)?|[Ee]merg(?:ency)?`}, //nolint:revive // regex literal
	// Log formats
	{"SYSLOGBASE", `%{SYSLOGTIMESTAMP:timestamp} (?:%{SYSLOGFACILITY} )?%{SYSLOGHOST:logsource} %{SYSLOGPROG}:`},
	{"COMMONAPACHELOG", `%{IPORHOST:clientip} %{HTTPDUSER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%{NUMBER:bytes}|-)`}, //nolint:revive // regex literal
	{"COMBINEDAPACHELOG", `%{COMMONAPACHELOG} %{QS:referrer} %{QS:agent}`},
	{"HTTPD20_ERRORLOG", `\[%{HTTPDERROR_DATE:timestamp}\] \[%{LOGLEVEL:loglevel}\] (?:\[client %{IPORHOST:clientip}\] ){0,1}%{GREEDYDATA:errormsg}`},
	{"HTTPD24_ERRORLOG", `\[%{HTTPDERROR_DATE:timestamp}\] \[%{WORD:module}:%{LOGLEVEL:loglevel}\] \[pid %{POSINT:pid}(:tid %{NUMBER:tid})?\]( \(%{POSINT:proxy_errorcode}\)%{DATA:proxy_errormessage}:)?( \[client %{IPORHOST:client}:%{INT:clientport}\])? %{DATA:errorcode}: %{GREEDYDATA:message}`}, //nolint:revive // regex literal
	{"HTTPD_ERRORLOG", `%{HTTPD20_ERRORLOG}|%{HTTPD24_ERRORLOG}`},
}

// NewBase creates new Host that filled up with base patterns.
// To see all base patterns open 'base.go' file.
func NewBase() Host {
	h := Host{Patterns: make(map[string]string)}
	for _, p := range basePatterns {
		h.Must(p.name, p.expr)
	}
	return h
}
