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

package grokky

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

// NewBase creates new Host that filled up with base patterns.
// To see all base patterns open 'base.go' file.
func NewBase() Host {
	h := make(Host)
	//
	h.Must("USERNAME", `[a-zA-Z0-9._-]+`)
	h.Must("USER", `%{USERNAME}`)
	h.Must("EMAILLOCALPART", `[a-zA-Z][a-zA-Z0-9_.+-=:]+`)
	h.Must("HOSTNAME", `\b[0-9A-Za-z][0-9A-Za-z-]{0,62}(?:\.[0-9A-Za-z][0-9A-Za-z-]{0,62})*(\.?|\b)`)
	h.Must("EMAILADDRESS", `%{EMAILLOCALPART}@%{HOSTNAME}`)
	h.Must("HTTPDUSER", `%{EMAILADDRESS}|%{USER}`)
	h.Must("INT", `[+-]?(?:[0-9]+)`)
	h.Must("BASE10NUM", `[+-]?(?:(?:[0-9]+(?:\.[0-9]+)?)|(?:\.[0-9]+))`)
	h.Must("NUMBER", `%{BASE10NUM}`)
	h.Must("BASE16NUM", `[+-]?(?:0x)?(?:[0-9A-Fa-f]+)`)
	h.Must("BASE16FLOAT", `\b[+-]?(?:0x)?(?:(?:[0-9A-Fa-f]+(?:\.[0-9A-Fa-f]*)?)|(?:\.[0-9A-Fa-f]+))\b`)
	//
	h.Must("POSINT", `\b[1-9][0-9]*\b`)
	h.Must("NONNEGINT", `\b[0-9]+\b`)
	h.Must("WORD", `\b\w+\b`)
	h.Must("NOTSPACE", `\S+`)
	h.Must("SPACE", `\s*`)
	h.Must("DATA", `.*?`)
	h.Must("GREEDYDATA", `.*`)
	h.Must("QUOTEDSTRING", `("(\\.|[^\\"]+)+")|""|('(\\.|[^\\']+)+')|''|`+
		"(`(\\\\.|[^\\\\`]+)+`)|``")
	h.Must("UUID", `[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}`)
	// Networking
	h.Must("CISCOMAC", `(?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4}`)
	h.Must("WINDOWSMAC", `(?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2}`)
	h.Must("COMMONMAC", `(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}`)
	h.Must("MAC", `%{CISCOMAC}|%{WINDOWSMAC}|%{COMMONMAC}`)
	h.Must("IPV6", `((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?`)
	h.Must("IPV4", `(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)`)
	h.Must("IP", `%{IPV6}|%{IPV4}`)
	h.Must("IPORHOST", `%{IP}|%{HOSTNAME}`)
	h.Must("HOSTPORT", `%{IPORHOST}:%{POSINT}`)

	// paths
	h.Must("UNIXPATH", `(/([\w_%!$@:.,~-]+|\\.)*)+`)
	h.Must("TTY", `/dev/(pts|tty([pq])?)(\w+)?/?(?:[0-9]+)`)
	h.Must("WINPATH", `(?:[A-Za-z]+:|\\)(?:\\[^\\?*]*)+`)
	h.Must("PATH", `%{UNIXPATH}|%{WINPATH}`)
	h.Must("URIPROTO", `[A-Za-z]+(\+[A-Za-z+]+)?`)
	h.Must("URIHOST", `%{IPORHOST}(?::%{POSINT:port})?`)
	// uripath comes loosely from RFC1738, but mostly from what Firefox
	// doesn't turn into %XX
	h.Must("URIPATH", `(?:/[A-Za-z0-9$.+!*'(){},~:;=@#%_\-]*)+`)
	h.Must("URIPARAM", `\?[A-Za-z0-9$.+!*'|(){},~@#%&/=:;_?\-\[\]<>]*`)
	h.Must("URIPATHPARAM", `%{URIPATH}(?:%{URIPARAM})?`)
	h.Must("URI", `%{URIPROTO}://(?:%{USER}(?::[^@]*)?@)?(?:%{URIHOST})?(?:%{URIPATHPARAM})?`)
	// Months: January, Feb, 3, 03, 12, December
	h.Must("MONTH", `\bJan(?:uary|uar)?|Feb(?:ruary|ruar)?|M(?:a|ä)?r(?:ch|z)?|Apr(?:il)?|Ma(?:y|i)?|Jun(?:e|i)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|O(?:c|k)?t(?:ober)?|Nov(?:ember)?|De(?:c|z)(?:ember)?\b`)
	h.Must("MONTHNUM", `0?[1-9]|1[0-2]`)
	h.Must("MONTHNUM2", `0[1-9]|1[0-2]`)
	h.Must("MONTHDAY", `(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9]`)
	// Days: Monday, Tue, Thu, etc...
	h.Must("DAY", `Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|Sat(?:urday)?|Sun(?:day)?`)
	// Years?
	h.Must("YEAR", `(?:\d\d){1,2}`)
	h.Must("HOUR", `2[0123]|[01]?[0-9]`)
	h.Must("MINUTE", `[0-5][0-9]`)
	// '60' is a leap second in most time standards and thus is valid.
	h.Must("SECOND", `(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?`)
	h.Must("TIME", `%{HOUR}:%{MINUTE}:%{SECOND}`)
	// datestamp is YYYY/MM/DD-HH:MM:SS.UUUU (or something like it)
	h.Must("DATE_US", `%{MONTHNUM}[/-]%{MONTHDAY}[/-]%{YEAR}`)
	h.Must("DATE_EU", `%{MONTHDAY}[./-]%{MONTHNUM}[./-]%{YEAR}`)
	// I really don't know how it's called
	h.Must("DATE_X", `%{YEAR}/%{MONTHNUM2}/%{MONTHDAY}`)
	h.Must("ISO8601_TIMEZONE", `Z|[+-]%{HOUR}(?::?%{MINUTE})`)
	h.Must("ISO8601_SECOND", `%{SECOND}|60`)
	h.Must("TIMESTAMP_ISO8601", `%{YEAR}-%{MONTHNUM}-%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::?%{SECOND})?%{ISO8601_TIMEZONE}?`)
	h.Must("DATE", `%{DATE_US}|%{DATE_EU}|%{DATE_X}`)
	h.Must("DATESTAMP", `%{DATE}[- ]%{TIME}`)
	h.Must("TZ", `[A-Z]{3}`)
	h.Must("NUMTZ", `[+-]\d{4}`)
	h.Must("DATESTAMP_RFC822", `%{DAY} %{MONTH} %{MONTHDAY} %{YEAR} %{TIME} %{TZ}`)
	h.Must("DATESTAMP_RFC2822", `%{DAY}, %{MONTHDAY} %{MONTH} %{YEAR} %{TIME} %{ISO8601_TIMEZONE}`)
	h.Must("DATESTAMP_OTHER", `%{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{TZ} %{YEAR}`)
	h.Must("DATESTAMP_EVENTLOG", `%{YEAR}%{MONTHNUM2}%{MONTHDAY}%{HOUR}%{MINUTE}%{SECOND}`)
	h.Must("HTTPDERROR_DATE", `%{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{YEAR}`)
	// golang time patterns
	h.Must("ANSIC", `%{DAY} %{MONTH} [_123]\d %{TIME} %{YEAR}"`)
	h.Must("UNIXDATE", `%{DAY} %{MONTH} [_123]\d %{TIME} %{TZ} %{YEAR}`)
	h.Must("RUBYDATE", `%{DAY} %{MONTH} [0-3]\d %{TIME} %{NUMTZ} %{YEAR}`)
	h.Must("RFC822Z", `[0-3]\d %{MONTH} %{YEAR} %{TIME} %{NUMTZ}`)
	h.Must("RFC850", `%{DAY}, [0-3]\d-%{MONTH}-%{YEAR} %{TIME} %{TZ}`)
	h.Must("RFC1123", `%{DAY}, [0-3]\d %{MONTH} %{YEAR} %{TIME} %{TZ}`)
	h.Must("RFC1123Z", `%{DAY}, [0-3]\d %{MONTH} %{YEAR} %{TIME} %{NUMTZ}`)
	h.Must("RFC3339", `%{YEAR}-[01]\d-[0-3]\dT%{TIME}%{ISO8601_TIMEZONE}`)
	h.Must("RFC3339NANO", `%{YEAR}-[01]\d-[0-3]\dT%{TIME}\.\d{9}%{ISO8601_TIMEZONE}`)
	h.Must("KITCHEN", `\d{1,2}:\d{2}(AM|PM|am|pm)`)
	// Syslog Dates: Month Day HH:MM:SS
	h.Must("SYSLOGTIMESTAMP", `%{MONTH} +%{MONTHDAY} %{TIME}`)
	h.Must("PROG", `[\x21-\x5a\x5c\x5e-\x7e]+`)
	h.Must("SYSLOGPROG", `%{PROG:program}(?:\[%{POSINT:pid}\])?`)
	h.Must("SYSLOGHOST", `%{IPORHOST}`)
	h.Must("SYSLOGFACILITY", `<%{NONNEGINT:facility}.%{NONNEGINT:priority}>`)
	h.Must("HTTPDATE", `%{MONTHDAY}/%{MONTH}/%{YEAR}:%{TIME} %{INT}`)
	// Shortcuts
	h.Must("QS", `%{QUOTEDSTRING}`)
	// Log Levels
	h.Must("LOGLEVEL", `[Aa]lert|ALERT|[Tt]race|TRACE|[Dd]ebug|DEBUG|[Nn]otice|NOTICE|[Ii]nfo|INFO|[Ww]arn?(?:ing)?|WARN?(?:ING)?|[Ee]rr?(?:or)?|ERR?(?:OR)?|[Cc]rit?(?:ical)?|CRIT?(?:ICAL)?|[Ff]atal|FATAL|[Ss]evere|SEVERE|EMERG(?:ENCY)?|[Ee]merg(?:ency)?`)
	// Log formats
	h.Must("SYSLOGBASE", `%{SYSLOGTIMESTAMP:timestamp} (?:%{SYSLOGFACILITY} )?%{SYSLOGHOST:logsource} %{SYSLOGPROG}:`)
	h.Must("COMMONAPACHELOG", `%{IPORHOST:clientip} %{HTTPDUSER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%{NUMBER:bytes}|-)`)
	h.Must("COMBINEDAPACHELOG", `%{COMMONAPACHELOG} %{QS:referrer} %{QS:agent}`)
	h.Must("HTTPD20_ERRORLOG", `\[%{HTTPDERROR_DATE:timestamp}\] \[%{LOGLEVEL:loglevel}\] (?:\[client %{IPORHOST:clientip}\] ){0,1}%{GREEDYDATA:errormsg}`)
	h.Must("HTTPD24_ERRORLOG", `\[%{HTTPDERROR_DATE:timestamp}\] \[%{WORD:module}:%{LOGLEVEL:loglevel}\] \[pid %{POSINT:pid}(:tid %{NUMBER:tid})?\]( \(%{POSINT:proxy_errorcode}\)%{DATA:proxy_errormessage}:)?( \[client %{IPORHOST:client}:%{POSINT:clientport}\])? %{DATA:errorcode}: %{GREEDYDATA:message}`)
	h.Must("HTTPD_ERRORLOG", `%{HTTPD20_ERRORLOG}|%{HTTPD24_ERRORLOG}`)
	return h
}
