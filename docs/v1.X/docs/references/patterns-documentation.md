# Patterns documentation

You will find here a generated documentation of all the patterns loaded by crowdsec.
They are sorted by pattern length, and are meant to be used in parsers, in the form %{PATTERN_NAME}.


## MONGO3_SEVERITY

Pattern :
```
\w
```

## GREEDYDATA

Pattern :
```
.*
```

## DATA

Pattern :
```
.*?
```

## NOTSPACE

Pattern :
```
\S+
```

## SPACE

Pattern :
```
\s*
```

## RAIL_ACTION

Pattern :
```
\w+
```

## JAVALOGMESSAGE

Pattern :
```
(.*)
```

## DAY2

Pattern :
```
\d{2}
```

## NOTDQUOTE

Pattern :
```
[^"]*
```

## RAILS_CONSTROLLER

Pattern :
```
[^#]+
```

## RUUID

Pattern :
```
\s{32}
```

## SYSLOG5424PRINTASCII

Pattern :
```
[!-~]+
```

## BACULA_VERSION

Pattern :
```
%{USER}
```

## WORD

Pattern :
```
\b\w+\b
```

## BACULA_JOB

Pattern :
```
%{USER}
```

## CRON_ACTION

Pattern :
```
[A-Z ]+
```

## BACULA_VOLUME

Pattern :
```
%{USER}
```

## BACULA_DEVICE

Pattern :
```
%{USER}
```

## TZ

Pattern :
```
[A-Z]{3}
```

## NUMTZ

Pattern :
```
[+-]\d{4}
```

## MONGO3_COMPONENT

Pattern :
```
%{WORD}|-
```

## MONGO_WORDDASH

Pattern :
```
\b[\w-]+\b
```

## NAGIOS_TYPE_HOST_ALERT

Pattern :
```
HOST ALERT
```

## NONNEGINT

Pattern :
```
\b[0-9]+\b
```

## MINUTE

Pattern :
```
[0-5][0-9]
```

## BACULA_DEVICEPATH

Pattern :
```
%{UNIXPATH}
```

## SYSLOGHOST

Pattern :
```
%{IPORHOST}
```

## REDISLOG1

Pattern :
```
%{REDISLOG}
```

## USER

Pattern :
```
%{USERNAME}
```

## NUMBER

Pattern :
```
%{BASE10NUM}
```

## SYSLOG5424SD

Pattern :
```
\[%{DATA}\]+
```

## ISO8601_SECOND

Pattern :
```
%{SECOND}|60
```

## NGUSER

Pattern :
```
%{NGUSERNAME}
```

## MONTHNUM2

Pattern :
```
0[1-9]|1[0-2]
```

## BACULA_HOST

Pattern :
```
[a-zA-Z0-9-]+
```

## EXIM_PID

Pattern :
```
\[%{POSINT}\]
```

## NAGIOS_TYPE_SERVICE_ALERT

Pattern :
```
SERVICE ALERT
```

## YEAR

Pattern :
```
(?:\d\d){1,2}
```

## MONTHNUM

Pattern :
```
0?[1-9]|1[0-2]
```

## CISCO_XLATE_TYPE

Pattern :
```
static|dynamic
```

## RAILS_CONTEXT

Pattern :
```
(?:%{DATA}\n)*
```

## BACULA_LOG_ENDPRUNE

Pattern :
```
End auto prune.
```

## POSINT

Pattern :
```
\b[1-9][0-9]*\b
```

## INT

Pattern :
```
[+-]?(?:[0-9]+)
```

## USERNAME

Pattern :
```
[a-zA-Z0-9._-]+
```

## IP

Pattern :
```
%{IPV6}|%{IPV4}
```

## QS

Pattern :
```
%{QUOTEDSTRING}
```

## MODSECRULEVERS

Pattern :
```
\[ver "[^"]+"\]
```

## NAGIOS_TYPE_EXTERNAL_COMMAND

Pattern :
```
EXTERNAL COMMAND
```

## NAGIOS_EC_ENABLE_SVC_CHECK

Pattern :
```
ENABLE_SVC_CHECK
```

## IPORHOST

Pattern :
```
%{IP}|%{HOSTNAME}
```

## NAGIOS_EC_ENABLE_HOST_CHECK

Pattern :
```
ENABLE_HOST_CHECK
```

## NAGIOS_TYPE_HOST_NOTIFICATION

Pattern :
```
HOST NOTIFICATION
```

## NAGIOS_EC_DISABLE_SVC_CHECK

Pattern :
```
DISABLE_SVC_CHECK
```

## NAGIOS_TYPE_PASSIVE_HOST_CHECK

Pattern :
```
PASSIVE HOST CHECK
```

## NAGIOS_TYPE_HOST_EVENT_HANDLER

Pattern :
```
HOST EVENT HANDLER
```

## HOUR

Pattern :
```
2[0123]|[01]?[0-9]
```

## DATESTAMP

Pattern :
```
%{DATE}[- ]%{TIME}
```

## NAGIOS_TYPE_CURRENT_HOST_STATE

Pattern :
```
CURRENT HOST STATE
```

## NAGIOS_EC_DISABLE_HOST_CHECK

Pattern :
```
DISABLE_HOST_CHECK
```

## NGUSERNAME

Pattern :
```
[a-zA-Z\.\@\-\+_%]+
```

## NAGIOS_TYPE_HOST_FLAPPING_ALERT

Pattern :
```
HOST FLAPPING ALERT
```

## NAGIOS_TYPE_HOST_DOWNTIME_ALERT

Pattern :
```
HOST DOWNTIME ALERT
```

## JAVAFILE

Pattern :
```
(?:[A-Za-z0-9_. -]+)
```

## NAGIOS_TYPE_SERVICE_NOTIFICATION

Pattern :
```
SERVICE NOTIFICATION
```

## BACULA_LOG_BEGIN_PRUNE_FILES

Pattern :
```
Begin pruning Files.
```

## NAGIOS_TYPE_CURRENT_SERVICE_STATE

Pattern :
```
CURRENT SERVICE STATE
```

## NAGIOS_TYPE_PASSIVE_SERVICE_CHECK

Pattern :
```
PASSIVE SERVICE CHECK
```

## NAGIOS_TYPE_TIMEPERIOD_TRANSITION

Pattern :
```
TIMEPERIOD TRANSITION
```

## HOSTPORT

Pattern :
```
%{IPORHOST}:%{POSINT}
```

## NAGIOS_TYPE_SERVICE_EVENT_HANDLER

Pattern :
```
SERVICE EVENT HANDLER
```

## NAGIOS_EC_SCHEDULE_HOST_DOWNTIME

Pattern :
```
SCHEDULE_HOST_DOWNTIME
```

## EXIM_FLAGS

Pattern :
```
(<=|[-=>*]>|[*]{2}|==)
```

## NAGIOS_TYPE_SERVICE_DOWNTIME_ALERT

Pattern :
```
SERVICE DOWNTIME ALERT
```

## EXIM_SUBJECT

Pattern :
```
(T=%{QS:exim_subject})
```

## PATH

Pattern :
```
%{UNIXPATH}|%{WINPATH}
```

## NAGIOS_TYPE_SERVICE_FLAPPING_ALERT

Pattern :
```
SERVICE FLAPPING ALERT
```

## SSHD_CORRUPT_MAC

Pattern :
```
Corrupted MAC on input
```

## BACULA_LOG_NOPRUNE_JOBS

Pattern :
```
No Jobs found to prune.
```

## HTTPDUSER

Pattern :
```
%{EMAILADDRESS}|%{USER}
```

## BACULA_LOG_NOPRUNE_FILES

Pattern :
```
No Files found to prune.
```

## NAGIOS_EC_ENABLE_SVC_NOTIFICATIONS

Pattern :
```
ENABLE_SVC_NOTIFICATIONS
```

## BACULA_CAPACITY

Pattern :
```
%{INT}{1,3}(,%{INT}{3})*
```

## EXIM_PROTOCOL

Pattern :
```
(P=%{NOTSPACE:protocol})
```

## URIPROTO

Pattern :
```
[A-Za-z]+(\+[A-Za-z+]+)?
```

## PROG

Pattern :
```
[\x21-\x5a\x5c\x5e-\x7e]+
```

## NAGIOS_EC_ENABLE_HOST_NOTIFICATIONS

Pattern :
```
ENABLE_HOST_NOTIFICATIONS
```

## NAGIOS_EC_PROCESS_HOST_CHECK_RESULT

Pattern :
```
PROCESS_HOST_CHECK_RESULT
```

## BACULA_LOG_VSS

Pattern :
```
(Generate )?VSS (Writer)?
```

## NAGIOS_EC_DISABLE_SVC_NOTIFICATIONS

Pattern :
```
DISABLE_SVC_NOTIFICATIONS
```

## NAGIOS_EC_SCHEDULE_SERVICE_DOWNTIME

Pattern :
```
SCHEDULE_SERVICE_DOWNTIME
```

## MONGO_QUERY

Pattern :
```
\{ \{ .* \} ntoreturn: \}
```

## URIPATHPARAM

Pattern :
```
%{URIPATH}(?:%{URIPARAM})?
```

## NAGIOS_EC_DISABLE_HOST_NOTIFICATIONS

Pattern :
```
DISABLE_HOST_NOTIFICATIONS
```

## UNIXPATH

Pattern :
```
(/([\w_%!$@:.,~-]+|\\.)*)+
```

## KITCHEN

Pattern :
```
\d{1,2}:\d{2}(AM|PM|am|pm)
```

## NAGIOSTIME

Pattern :
```
\[%{NUMBER:nagios_epoch}\]
```

## EMAILLOCALPART

Pattern :
```
[a-zA-Z][a-zA-Z0-9_.+-=:]+
```

## JAVATHREAD

Pattern :
```
(?:[A-Z]{2}-Processor[\d]+)
```

## TIME

Pattern :
```
%{HOUR}:%{MINUTE}:%{SECOND}
```

## EXIM_MSG_SIZE

Pattern :
```
(S=%{NUMBER:exim_msg_size})
```

## RUBY_LOGLEVEL

Pattern :
```
DEBUG|FATAL|ERROR|WARN|INFO
```

## BASE16NUM

Pattern :
```
[+-]?(?:0x)?(?:[0-9A-Fa-f]+)
```

## ISO8601_TIMEZONE

Pattern :
```
Z|[+-]%{HOUR}(?::?%{MINUTE})
```

## REDISTIMESTAMP

Pattern :
```
%{MONTHDAY} %{MONTH} %{TIME}
```

## NAGIOS_EC_PROCESS_SERVICE_CHECK_RESULT

Pattern :
```
PROCESS_SERVICE_CHECK_RESULT
```

## SSHD_PACKET_CORRUPT

Pattern :
```
Disconnecting: Packet corrupt
```

## SYSLOG5424PRI

Pattern :
```
<%{NONNEGINT:syslog5424_pri}>
```

## EMAILADDRESS

Pattern :
```
%{EMAILLOCALPART}@%{HOSTNAME}
```

## MODSECRULEID

Pattern :
```
\[id %{QUOTEDSTRING:ruleid}\]
```

## SYSLOGTIMESTAMP

Pattern :
```
%{MONTH} +%{MONTHDAY} %{TIME}
```

## NAGIOS_EC_ENABLE_HOST_SVC_NOTIFICATIONS

Pattern :
```
ENABLE_HOST_SVC_NOTIFICATIONS
```

## NAGIOS_EC_DISABLE_HOST_SVC_NOTIFICATIONS

Pattern :
```
DISABLE_HOST_SVC_NOTIFICATIONS
```

## EXIM_HEADER_ID

Pattern :
```
(id=%{NOTSPACE:exim_header_id})
```

## URIHOST

Pattern :
```
%{IPORHOST}(?::%{POSINT:port})?
```

## DATE

Pattern :
```
%{DATE_US}|%{DATE_EU}|%{DATE_X}
```

## SSHD_TUNN_TIMEOUT

Pattern :
```
Timeout, client not responding.
```

## MCOLLECTIVEAUDIT

Pattern :
```
%{TIMESTAMP_ISO8601:timestamp}:
```

## CISCOTAG

Pattern :
```
[A-Z0-9]+-%{INT}-(?:[A-Z0-9_]+)
```

## MODSECRULEREV

Pattern :
```
\[rev %{QUOTEDSTRING:rulerev}\]
```

## HAPROXYCAPTUREDREQUESTHEADERS

Pattern :
```
%{DATA:captured_request_headers}
```

## CISCO_INTERVAL

Pattern :
```
first hit|%{INT}-second interval
```

## DATE_X

Pattern :
```
%{YEAR}/%{MONTHNUM2}/%{MONTHDAY}
```

## SSHD_INIT

Pattern :
```
%{SSHD_LISTEN}|%{SSHD_TERMINATE}
```

## WINPATH

Pattern :
```
(?:[A-Za-z]+:|\\)(?:\\[^\\?*]*)+
```

## HAPROXYCAPTUREDRESPONSEHEADERS

Pattern :
```
%{DATA:captured_response_headers}
```

## MODSECURI

Pattern :
```
\[uri ["']%{DATA:targeturi}["']\]
```

## CISCO_DIRECTION

Pattern :
```
Inbound|inbound|Outbound|outbound
```

## MODSECRULEDATA

Pattern :
```
\[data %{QUOTEDSTRING:ruledata}\]
```

## MODSECRULELINE

Pattern :
```
\[line %{QUOTEDSTRING:ruleline}\]
```

## MODSECRULEFILE

Pattern :
```
\[file %{QUOTEDSTRING:rulefile}\]
```

## SECOND

Pattern :
```
(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?
```

## BACULA_LOG_CANCELLING

Pattern :
```
Cancelling duplicate JobId=%{INT}.
```

## MODSECRULEMSG

Pattern :
```
\[msg %{QUOTEDSTRING:rulemessage}\]
```

## SSHD_TUNN_ERR3

Pattern :
```
error: bind: Address already in use
```

## BACULA_LOG_STARTRESTORE

Pattern :
```
Start Restore Job %{BACULA_JOB:job}
```

## SYSLOGLINE

Pattern :
```
%{SYSLOGBASE2} %{GREEDYDATA:message}
```

## COMMONMAC

Pattern :
```
(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}
```

## WINDOWSMAC

Pattern :
```
(?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2}
```

## SYSLOGPROG

Pattern :
```
%{PROG:program}(?:\[%{POSINT:pid}\])?
```

## JAVAMETHOD

Pattern :
```
(?:(<init>)|[a-zA-Z$_][a-zA-Z$_0-9]*)
```

## DATE_US

Pattern :
```
%{MONTHNUM}[/-]%{MONTHDAY}[/-]%{YEAR}
```

## CISCOMAC

Pattern :
```
(?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4}
```

## MODSECUID

Pattern :
```
\[unique_id %{QUOTEDSTRING:uniqueid}\]
```

## MAC

Pattern :
```
%{CISCOMAC}|%{WINDOWSMAC}|%{COMMONMAC}
```

## ELB_URIPATHPARAM

Pattern :
```
%{URIPATH:path}(?:%{URIPARAM:params})?
```

## BACULA_LOG_NOPRIOR

Pattern :
```
No prior Full backup Job record found.
```

## MODSECMATCHOFFSET

Pattern :
```
\[offset %{QUOTEDSTRING:matchoffset}\]
```

## BACULA_TIMESTAMP

Pattern :
```
%{MONTHDAY}-%{MONTH} %{HOUR}:%{MINUTE}
```

## MODSECHOSTNAME

Pattern :
```
\[hostname ['"]%{DATA:targethost}["']\]
```

## TTY

Pattern :
```
/dev/(pts|tty([pq])?)(\w+)?/?(?:[0-9]+)
```

## DATE_EU

Pattern :
```
%{MONTHDAY}[./-]%{MONTHNUM}[./-]%{YEAR}
```

## URIPATH

Pattern :
```
(?:/[A-Za-z0-9$.+!*'(){},~:;=@#%_\-]*)+
```

## HTTPD_ERRORLOG

Pattern :
```
%{HTTPD20_ERRORLOG}|%{HTTPD24_ERRORLOG}
```

## MONTHDAY

Pattern :
```
(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9]
```

## BACULA_LOG_USEDEVICE

Pattern :
```
Using Device \"%{BACULA_DEVICE:device}\"
```

## RFC822Z

Pattern :
```
[0-3]\d %{MONTH} %{YEAR} %{TIME} %{NUMTZ}
```

## MODSECRULESEVERITY

Pattern :
```
\[severity ["']%{WORD:ruleseverity}["']\]
```

## ANSIC

Pattern :
```
%{DAY} %{MONTH} [_123]\d %{TIME} %{YEAR}"
```

## GENERICAPACHEERROR

Pattern :
```
%{APACHEERRORPREFIX} %{GREEDYDATA:message}
```

## SSHD_CONN_CLOSE

Pattern :
```
Connection closed by %{IP:sshd_client_ip}$
```

## CISCOTIMESTAMP

Pattern :
```
%{MONTH} +%{MONTHDAY}(?: %{YEAR})? %{TIME}
```

## APACHEERRORTIME

Pattern :
```
%{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{YEAR}
```

## CISCOFW104004

Pattern :
```
\((?:Primary|Secondary)\) Switching to OK\.
```

## HTTPDATE

Pattern :
```
%{MONTHDAY}/%{MONTH}/%{YEAR}:%{TIME} %{INT}
```

## HTTPDERROR_DATE

Pattern :
```
%{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{YEAR}
```

## EXIM_QT

Pattern :
```
((\d+y)?(\d+w)?(\d+d)?(\d+h)?(\d+m)?(\d+s)?)
```

## BACULA_LOG_NOJOBSTAT

Pattern :
```
Fatal error: No Job status returned from FD.
```

## NAGIOS_WARNING

Pattern :
```
Warning:%{SPACE}%{GREEDYDATA:nagios_message}
```

## EXIM_MSGID

Pattern :
```
[0-9A-Za-z]{6}-[0-9A-Za-z]{6}-[0-9A-Za-z]{2}
```

## BASE10NUM

Pattern :
```
[+-]?(?:(?:[0-9]+(?:\.[0-9]+)?)|(?:\.[0-9]+))
```

## REDISLOG

Pattern :
```
\[%{POSINT:pid}\] %{REDISTIMESTAMP:time} \*\s
```

## URIPARAM

Pattern :
```
\?[A-Za-z0-9$.+!*'|(){},~@#%&/=:;_?\-\[\]<>]*
```

## COMBINEDAPACHELOG

Pattern :
```
%{COMMONAPACHELOG} %{QS:referrer} %{QS:agent}
```

## SYSLOGFACILITY

Pattern :
```
<%{NONNEGINT:facility}.%{NONNEGINT:priority}>
```

## RFC1123

Pattern :
```
%{DAY}, [0-3]\d %{MONTH} %{YEAR} %{TIME} %{TZ}
```

## UNIXDATE

Pattern :
```
%{DAY} %{MONTH} [_123]\d %{TIME} %{TZ} %{YEAR}
```

## RFC850

Pattern :
```
%{DAY}, [0-3]\d-%{MONTH}-%{YEAR} %{TIME} %{TZ}
```

## SYSLOG5424LINE

Pattern :
```
%{SYSLOG5424BASE} +%{GREEDYDATA:syslog5424_msg}
```

## CISCOFW104003

Pattern :
```
\((?:Primary|Secondary)\) Switching to FAILED\.
```

## RUBYDATE

Pattern :
```
%{DAY} %{MONTH} [0-3]\d %{TIME} %{NUMTZ} %{YEAR}
```

## BACULA_LOG_NOOPEN

Pattern :
```
\s+Cannot open %{DATA}: ERR=%{GREEDYDATA:berror}
```

## BACULA_LOG_STARTJOB

Pattern :
```
Start Backup JobId %{INT}, Job=%{BACULA_JOB:job}
```

## DATESTAMP_RFC822

Pattern :
```
%{DAY} %{MONTH} %{MONTHDAY} %{YEAR} %{TIME} %{TZ}
```

## DATESTAMP_OTHER

Pattern :
```
%{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{TZ} %{YEAR}
```

## RFC3339

Pattern :
```
%{YEAR}-[01]\d-[0-3]\dT%{TIME}%{ISO8601_TIMEZONE}
```

## RFC1123Z

Pattern :
```
%{DAY}, [0-3]\d %{MONTH} %{YEAR} %{TIME} %{NUMTZ}
```

## BACULA_LOG_NOSTAT

Pattern :
```
\s+Could not stat %{DATA}: ERR=%{GREEDYDATA:berror}
```

## SSHD_TERMINATE

Pattern :
```
Received signal %{NUMBER:sshd_signal}; terminating.
```

## UUID

Pattern :
```
[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}
```

## SSHD_LOGOUT_ERR

Pattern :
```
syslogin_perform_logout: logout\(\) returned an error
```

## RCONTROLLER

Pattern :
```
%{RAILS_CONSTROLLER:controller}#%{RAIL_ACTION:action}
```

## JAVACLASS

Pattern :
```
(?:[a-zA-Z$_][a-zA-Z$_0-9]*\.)*[a-zA-Z$_][a-zA-Z$_0-9]*
```

## DATESTAMP_EVENTLOG

Pattern :
```
%{YEAR}%{MONTHNUM2}%{MONTHDAY}%{HOUR}%{MINUTE}%{SECOND}
```

## NGINXERRTIME

Pattern :
```
%{YEAR}/%{MONTHNUM2}/%{DAY2} %{HOUR}:%{MINUTE}:%{SECOND}
```

## BACULA_LOG_BEGIN_PRUNE_JOBS

Pattern :
```
Begin pruning Jobs older than %{INT} month %{INT} days .
```

## RFC3339NANO

Pattern :
```
%{YEAR}-[01]\d-[0-3]\dT%{TIME}\.\d{9}%{ISO8601_TIMEZONE}
```

## BACULA_LOG_MARKCANCEL

Pattern :
```
JobId %{INT}, Job %{BACULA_JOB:job} marked to be canceled.
```

## BACULA_LOG_NEW_VOLUME

Pattern :
```
Created new Volume \"%{BACULA_VOLUME:volume}\" in catalog.
```

## SSHD_TCPWRAP_FAIL5

Pattern :
```
warning: can't get client address: Connection reset by peer
```

## EXIM_INTERFACE

Pattern :
```
(I=\[%{IP:exim_interface}\](:%{NUMBER:exim_interface_port}))
```

## BACULA_LOG_NOOPENDIR

Pattern :
```
\s+Could not open directory %{DATA}: ERR=%{GREEDYDATA:berror}
```

## BACULA_LOG_CLIENT_RBJ

Pattern :
```
shell command: run ClientRunBeforeJob \"%{GREEDYDATA:runjob}\"
```

## SSHD_IDENT_FAIL

Pattern :
```
Did not receive identification string from %{IP:sshd_client_ip}
```

## DATESTAMP_RFC2822

Pattern :
```
%{DAY}, %{MONTHDAY} %{MONTH} %{YEAR} %{TIME} %{ISO8601_TIMEZONE}
```

## BACULA_LOG_MAXSTART

Pattern :
```
Fatal error: Job canceled because max start delay time exceeded.
```

## QUOTEDSTRING

Pattern :
```
("(\\.|[^\\"]+)+")|""|('(\\.|[^\\']+)+')|''|(`(\\.|[^\\`]+)+`)|``
```

## REDISLOG2

Pattern :
```
%{POSINT:pid}:M %{REDISTIMESTAMP:time} [*#] %{GREEDYDATA:message}
```

## BACULA_LOG_PRUNED_JOBS

Pattern :
```
Pruned %{INT} Jobs* for client %{BACULA_HOST:client} from catalog.
```

## RT_FLOW_EVENT

Pattern :
```
(RT_FLOW_SESSION_CREATE|RT_FLOW_SESSION_CLOSE|RT_FLOW_SESSION_DENY)
```

## BACULA_LOG_NOSUIT

Pattern :
```
No prior or suitable Full backup found in catalog. Doing FULL backup.
```

## CISCOFW302010

Pattern :
```
%{INT:connection_count} in use, %{INT:connection_count_max} most used
```

## SSHD_INVAL_USER

Pattern :
```
Invalid user\s*%{USERNAME:sshd_invalid_user}? from %{IP:sshd_client_ip}
```

## SSHD_SESSION_CLOSE

Pattern :
```
pam_unix\(sshd:session\): session closed for user %{USERNAME:sshd_user}
```

## MONGO_LOG

Pattern :
```
%{SYSLOGTIMESTAMP:timestamp} \[%{WORD:component}\] %{GREEDYDATA:message}
```

## BACULA_LOG_READYAPPEND

Pattern :
```
Ready to append to end of Volume \"%{BACULA_VOLUME:volume}\" size=%{INT}
```

## CRONLOG

Pattern :
```
%{SYSLOGBASE} \(%{USER:user}\) %{CRON_ACTION:action} \(%{DATA:message}\)
```

## BACULA_LOG_JOB

Pattern :
```
(Error: )?Bacula %{BACULA_HOST} %{BACULA_VERSION} \(%{BACULA_VERSION}\):
```

## SSHD_LISTEN

Pattern :
```
Server listening on %{IP:sshd_listen_ip} port %{NUMBER:sshd_listen_port}.
```

## URI

Pattern :
```
%{URIPROTO}://(?:%{USER}(?::[^@]*)?@)?(?:%{URIHOST})?(?:%{URIPATHPARAM})?
```

## RAILS3

Pattern :
```
%{RAILS3HEAD}(?:%{RPROCESSING})?%{RAILS_CONTEXT:context}(?:%{RAILS3FOOT})?
```

## BASE16FLOAT

Pattern :
```
\b[+-]?(?:0x)?(?:(?:[0-9A-Fa-f]+(?:\.[0-9A-Fa-f]*)?)|(?:\.[0-9A-Fa-f]+))\b
```

## HAPROXYTIME

Pattern :
```
%{HOUR:haproxy_hour}:%{MINUTE:haproxy_minute}(?::%{SECOND:haproxy_second})
```

## CISCOFW104001

Pattern :
```
\((?:Primary|Secondary)\) Switching to ACTIVE - %{GREEDYDATA:switch_reason}
```

## CATALINA_DATESTAMP

Pattern :
```
%{MONTH} %{MONTHDAY}, 20%{YEAR} %{HOUR}:?%{MINUTE}(?::?%{SECOND}) (?:AM|PM)
```

## CISCOFW105008

Pattern :
```
\((?:Primary|Secondary)\) Testing [Ii]nterface %{GREEDYDATA:interface_name}
```

## HOSTNAME

Pattern :
```
\b[0-9A-Za-z][0-9A-Za-z-]{0,62}(?:\.[0-9A-Za-z][0-9A-Za-z-]{0,62})*(\.?|\b)
```

## CISCOFW104002

Pattern :
```
\((?:Primary|Secondary)\) Switching to STANDBY - %{GREEDYDATA:switch_reason}
```

## BACULA_LOG_VOLUME_PREVWRITTEN

Pattern :
```
Volume \"%{BACULA_VOLUME:volume}\" previously written, moving to end of data.
```

## SSHD_BAD_VERSION

Pattern :
```
Bad protocol version identification '%{GREEDYDATA}' from %{IP:sshd_client_ip}
```

## BACULA_LOG_PRUNED_FILES

Pattern :
```
Pruned Files from %{INT} Jobs* for client %{BACULA_HOST:client} from catalog.
```

## SSHD_BADL_PREAUTH

Pattern :
```
Bad packet length %{NUMBER:sshd_packet_length}. \[%{GREEDYDATA:sshd_privsep}\]
```

## CATALINALOG

Pattern :
```
%{CATALINA_DATESTAMP:timestamp} %{JAVACLASS:class} %{JAVALOGMESSAGE:logmessage}
```

## RAILS_TIMESTAMP

Pattern :
```
%{YEAR}-%{MONTHNUM}-%{MONTHDAY} %{HOUR}:%{MINUTE}:%{SECOND} %{ISO8601_TIMEZONE}
```

## SSHD_TUNN_ERR1

Pattern :
```
error: connect_to %{IP:sshd_listen_ip} port %{NUMBER:sshd_listen_port}: failed.
```

## EXIM_DATE

Pattern :
```
%{YEAR:exim_year}-%{MONTHNUM:exim_month}-%{MONTHDAY:exim_day} %{TIME:exim_time}
```

## BACULA_LOG_DUPLICATE

Pattern :
```
Fatal error: JobId %{INT:duplicate} already running. Duplicate job not allowed.
```

## SSHD_REFUSE_CONN

Pattern :
```
refused connect from %{DATA:sshd_client_hostname} \(%{IPORHOST:sshd_client_ip}\)
```

## SSHD_TOOMANY_AUTH

Pattern :
```
Disconnecting: Too many authentication failures for %{USERNAME:sshd_invalid_user}
```

## BACULA_LOG_ALL_RECORDS_PRUNED

Pattern :
```
All records pruned from Volume \"%{BACULA_VOLUME:volume}\"; marking it \"Purged\"
```

## SSHD_DISR_PREAUTH

Pattern :
```
Disconnecting: %{GREEDYDATA:sshd_disconnect_status} \[%{GREEDYDATA:sshd_privsep}\]
```

## MCOLLECTIVE

Pattern :
```
., \[%{TIMESTAMP_ISO8601:timestamp} #%{POSINT:pid}\]%{SPACE}%{LOGLEVEL:event_level}
```

## BACULA_LOG_DIFF_FS

Pattern :
```
\s+%{UNIXPATH} is a different filesystem. Will not descend from %{UNIXPATH} into it.
```

## SSHD_TUNN_ERR2

Pattern :
```
error: channel_setup_fwd_listener: cannot listen to port: %{NUMBER:sshd_listen_port}
```

## CISCOFW321001

Pattern :
```
Resource '%{WORD:resource_name}' limit of %{POSINT:resource_limit} reached for system
```

## BACULA_LOG_NO_AUTH

Pattern :
```
Fatal error: Unable to authenticate with File daemon at %{HOSTNAME}. Possible causes:
```

## POSTGRESQL

Pattern :
```
%{DATESTAMP:timestamp} %{TZ} %{DATA:user_id} %{GREEDYDATA:connection_id} %{POSINT:pid}
```

## ELB_REQUEST_LINE

Pattern :
```
(?:%{WORD:verb} %{ELB_URI:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})
```

## SSHD_SESSION_OPEN

Pattern :
```
pam_unix\(sshd:session\): session opened for user %{USERNAME:sshd_user} by \(uid=\d+\)
```

## TOMCAT_DATESTAMP

Pattern :
```
20%{YEAR}-%{MONTHNUM}-%{MONTHDAY} %{HOUR}:?%{MINUTE}(?::?%{SECOND}) %{ISO8601_TIMEZONE}
```

## S3_REQUEST_LINE

Pattern :
```
(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})
```

## RAILS3FOOT

Pattern :
```
Completed %{NUMBER:response}%{DATA} in %{NUMBER:totalms}ms %{RAILS3PROFILE}%{GREEDYDATA}
```

## CISCOFW105004

Pattern :
```
\((?:Primary|Secondary)\) Monitoring on [Ii]nterface %{GREEDYDATA:interface_name} normal
```

## CISCOFW105003

Pattern :
```
\((?:Primary|Secondary)\) Monitoring on [Ii]nterface %{GREEDYDATA:interface_name} waiting
```

## BACULA_LOG_JOBEND

Pattern :
```
Job write elapsed time = %{DATA:elapsed}, Transfer rate = %{NUMBER} (K|M|G)? Bytes/second
```

## TIMESTAMP_ISO8601

Pattern :
```
%{YEAR}-%{MONTHNUM}-%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::?%{SECOND})?%{ISO8601_TIMEZONE}?
```

## SYSLOGBASE

Pattern :
```
%{SYSLOGTIMESTAMP:timestamp} (?:%{SYSLOGFACILITY} )?%{SYSLOGHOST:logsource} %{SYSLOGPROG}:
```

## SSHD_TUNN_ERR4

Pattern :
```
error: channel_setup_fwd_listener_tcpip: cannot listen to port: %{NUMBER:sshd_listen_port}
```

## MODSECPREFIX

Pattern :
```
%{APACHEERRORPREFIX} ModSecurity: %{NOTSPACE:modsecseverity}\. %{GREEDYDATA:modsecmessage}
```

## JAVASTACKTRACEPART

Pattern :
```
%{SPACE}at %{JAVACLASS:class}\.%{JAVAMETHOD:method}\(%{JAVAFILE:file}(?::%{NUMBER:line})?\)
```

## EXIM_REMOTE_HOST

Pattern :
```
(H=(%{NOTSPACE:remote_hostname} )?(\(%{NOTSPACE:remote_heloname}\) )?\[%{IP:remote_host}\])
```

## ELB_URI

Pattern :
```
%{URIPROTO:proto}://(?:%{USER}(?::[^@]*)?@)?(?:%{URIHOST:urihost})?(?:%{ELB_URIPATHPARAM})?
```

## DAY

Pattern :
```
Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|Sat(?:urday)?|Sun(?:day)?
```

## SSHD_TUNN

Pattern :
```
%{SSHD_TUNN_ERR1}|%{SSHD_TUNN_ERR2}|%{SSHD_TUNN_ERR3}|%{SSHD_TUNN_ERR4}|%{SSHD_TUNN_TIMEOUT}
```

## SSHD_SESSION_FAIL

Pattern :
```
pam_systemd\(sshd:session\): Failed to release session: %{GREEDYDATA:sshd_disconnect_status}
```

## BACULA_LOG_NOJOBS

Pattern :
```
There are no more Jobs associated with Volume \"%{BACULA_VOLUME:volume}\". Marking it purged.
```

## RPROCESSING

Pattern :
```
\W*Processing by %{RCONTROLLER} as %{NOTSPACE:format}(?:\W*Parameters: \{\%\{DATA:params}}\W*)?
```

## CISCOFW105009

Pattern :
```
\((?:Primary|Secondary)\) Testing on [Ii]nterface %{GREEDYDATA:interface_name} (?:Passed|Failed)
```

## SSHD_LOG

Pattern :
```
%{SSHD_INIT}|%{SSHD_NORMAL_LOG}|%{SSHD_PROBE_LOG}|%{SSHD_CORRUPTED}|%{SSHD_TUNN}|%{SSHD_PREAUTH}
```

## SSHD_DISC_PREAUTH

Pattern :
```
Disconnected from %{IP:sshd_client_ip} port %{NUMBER:sshd_port}\s*(?:\[%{GREEDYDATA:sshd_privsep}\]|)
```

## SSHD_REST_PREAUTH

Pattern :
```
Connection reset by %{IP:sshd_client_ip} port %{NUMBER:sshd_port}\s*(?:\[%{GREEDYDATA:sshd_privsep}\]|)
```

## TOMCATLOG

Pattern :
```
%{TOMCAT_DATESTAMP:timestamp} \| %{LOGLEVEL:level} \| %{JAVACLASS:class} - %{JAVALOGMESSAGE:logmessage}
```

## SSHD_CLOS_PREAUTH

Pattern :
```
Connection closed by %{IP:sshd_client_ip} port %{NUMBER:sshd_port}\s*(?:\[%{GREEDYDATA:sshd_privsep}\]|)
```

## CISCO_TAGGED_SYSLOG

Pattern :
```
^<%{POSINT:syslog_pri}>%{CISCOTIMESTAMP:timestamp}( %{SYSLOGHOST:sysloghost})? ?: %%{CISCOTAG:ciscotag}:
```

## SSHD_INVA_PREAUTH

Pattern :
```
input_userauth_request: invalid user %{USERNAME:sshd_invalid_user}?\s*(?:\[%{GREEDYDATA:sshd_privsep}\]|)
```

## RAILS3HEAD

Pattern :
```
(?m)Started %{WORD:verb} "%{URIPATHPARAM:request}" for %{IPORHOST:clientip} at %{RAILS_TIMESTAMP:timestamp}
```

## CISCOFW105005

Pattern :
```
\((?:Primary|Secondary)\) Lost Failover communications with mate on [Ii]nterface %{GREEDYDATA:interface_name}
```

## BACULA_LOG_NEW_LABEL

Pattern :
```
Labeled new Volume \"%{BACULA_VOLUME:volume}\" on device \"%{BACULA_DEVICE:device}\" \(%{BACULA_DEVICEPATH}\).
```

## NAGIOS_EC_LINE_ENABLE_HOST_CHECK

Pattern :
```
%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_ENABLE_HOST_CHECK:nagios_command};%{DATA:nagios_hostname}
```

## COWRIE_NEW_CO

Pattern :
```
New connection: %{IPV4:source_ip}:[0-9]+ \(%{IPV4:dest_ip}:%{INT:dest_port}\) \[session: %{DATA:telnet_session}\]$
```

## CISCO_ACTION

Pattern :
```
Built|Teardown|Deny|Denied|denied|requested|permitted|denied by ACL|discarded|est-allowed|Dropping|created|deleted
```

## NAGIOS_EC_LINE_DISABLE_HOST_CHECK

Pattern :
```
%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_DISABLE_HOST_CHECK:nagios_command};%{DATA:nagios_hostname}
```

## CISCOFW402117

Pattern :
```
%{WORD:protocol}: Received a non-IPSec packet \(protocol= %{WORD:orig_protocol}\) from %{IP:src_ip} to %{IP:dst_ip}
```

## BACULA_LOG_WROTE_LABEL

Pattern :
```
Wrote label to prelabeled Volume \"%{BACULA_VOLUME:volume}\" on device \"%{BACULA_DEVICE}\" \(%{BACULA_DEVICEPATH}\)
```

## RAILS3PROFILE

Pattern :
```
(?:\(Views: %{NUMBER:viewms}ms \| ActiveRecord: %{NUMBER:activerecordms}ms|\(ActiveRecord: %{NUMBER:activerecordms}ms)?
```

## CISCOFW500004

Pattern :
```
%{CISCO_REASON:reason} for protocol=%{WORD:protocol}, from %{IP:src_ip}/%{INT:src_port} to %{IP:dst_ip}/%{INT:dst_port}
```

## NAGIOS_TIMEPERIOD_TRANSITION

Pattern :
```
%{NAGIOS_TYPE_TIMEPERIOD_TRANSITION:nagios_type}: %{DATA:nagios_service};%{DATA:nagios_unknown1};%{DATA:nagios_unknown2}
```

## NAGIOS_PASSIVE_HOST_CHECK

Pattern :
```
%{NAGIOS_TYPE_PASSIVE_HOST_CHECK:nagios_type}: %{DATA:nagios_hostname};%{DATA:nagios_state};%{GREEDYDATA:nagios_comment}
```

## NAGIOS_HOST_DOWNTIME_ALERT

Pattern :
```
%{NAGIOS_TYPE_HOST_DOWNTIME_ALERT:nagios_type}: %{DATA:nagios_hostname};%{DATA:nagios_state};%{GREEDYDATA:nagios_comment}
```

## NAGIOS_HOST_FLAPPING_ALERT

Pattern :
```
%{NAGIOS_TYPE_HOST_FLAPPING_ALERT:nagios_type}: %{DATA:nagios_hostname};%{DATA:nagios_state};%{GREEDYDATA:nagios_message}
```

## HTTPD20_ERRORLOG

Pattern :
```
\[%{HTTPDERROR_DATE:timestamp}\] \[%{LOGLEVEL:loglevel}\] (?:\[client %{IPORHOST:clientip}\] ){0,1}%{GREEDYDATA:errormsg}
```

## NGINXERROR

Pattern :
```
%{NGINXERRTIME:time} \[%{LOGLEVEL:loglevel}\] %{NONNEGINT:pid}#%{NONNEGINT:tid}: (\*%{NONNEGINT:cid} )?%{GREEDYDATA:message}
```

## MYSQL_AUTH_FAIL

Pattern :
```
%{TIMESTAMP_ISO8601:time} %{NUMBER} \[Note\] Access denied for user '%{DATA:user}'@'%{IP:source_ip}' \(using password: YES\)
```

## BACULA_LOG_MAX_CAPACITY

Pattern :
```
User defined maximum volume capacity %{BACULA_CAPACITY} exceeded on device \"%{BACULA_DEVICE:device}\" \(%{BACULA_DEVICEPATH}\)
```

## NAGIOS_EC_LINE_ENABLE_HOST_NOTIFICATIONS

Pattern :
```
%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_ENABLE_HOST_NOTIFICATIONS:nagios_command};%{GREEDYDATA:nagios_hostname}
```

## HAPROXYDATE

Pattern :
```
%{MONTHDAY:haproxy_monthday}/%{MONTH:haproxy_month}/%{YEAR:haproxy_year}:%{HAPROXYTIME:haproxy_time}.%{INT:haproxy_milliseconds}
```

## CISCOFW106021

Pattern :
```
%{CISCO_ACTION:action} %{WORD:protocol} reverse path check from %{IP:src_ip} to %{IP:dst_ip} on interface %{GREEDYDATA:interface}
```

## RUBY_LOGGER

Pattern :
```
[DFEWI], \[%{TIMESTAMP_ISO8601:timestamp} #%{POSINT:pid}\] *%{RUBY_LOGLEVEL:loglevel} -- +%{DATA:progname}: %{GREEDYDATA:message}
```

## NAGIOS_EC_LINE_DISABLE_HOST_NOTIFICATIONS

Pattern :
```
%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_DISABLE_HOST_NOTIFICATIONS:nagios_command};%{GREEDYDATA:nagios_hostname}
```

## CISCOFW110002

Pattern :
```
%{CISCO_REASON:reason} for %{WORD:protocol} from %{DATA:src_interface}:%{IP:src_ip}/%{INT:src_port} to %{IP:dst_ip}/%{INT:dst_port}
```

## NAGIOS_EC_LINE_ENABLE_HOST_SVC_NOTIFICATIONS

Pattern :
```
%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_ENABLE_HOST_SVC_NOTIFICATIONS:nagios_command};%{GREEDYDATA:nagios_hostname}
```

## NAGIOS_EC_LINE_DISABLE_HOST_SVC_NOTIFICATIONS

Pattern :
```
%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_DISABLE_HOST_SVC_NOTIFICATIONS:nagios_command};%{GREEDYDATA:nagios_hostname}
```

## SSHD_RMAP_FAIL

Pattern :
```
reverse mapping checking getaddrinfo for %{HOSTNAME:sshd_client_hostname} \[%{IP:sshd_client_ip}\] failed - POSSIBLE BREAK-IN ATTEMPT!
```

## HAPROXYHTTP

Pattern :
```
(?:%{SYSLOGTIMESTAMP:syslog_timestamp}|%{TIMESTAMP_ISO8601:timestamp8601}) %{IPORHOST:syslog_server} %{SYSLOGPROG}: %{HAPROXYHTTPBASE}
```

## SSHD_USER_FAIL

Pattern :
```
Failed password for invalid user %{USERNAME:sshd_invalid_user} from %{IP:sshd_client_ip} port %{NUMBER:sshd_port} %{WORD:sshd_protocol}
```

## SYSLOGBASE2

Pattern :
```
(?:%{SYSLOGTIMESTAMP:timestamp}|%{TIMESTAMP_ISO8601:timestamp8601}) (?:%{SYSLOGFACILITY} )?%{SYSLOGHOST:logsource}+(?: %{SYSLOGPROG}:|)
```

## SSHD_NORMAL_LOG

Pattern :
```
%{SSHD_SUCCESS}|%{SSHD_DISCONNECT}|%{SSHD_CONN_CLOSE}|%{SSHD_SESSION_OPEN}|%{SSHD_SESSION_CLOSE}|%{SSHD_SESSION_FAIL}|%{SSHD_LOGOUT_ERR}
```

## SSHD_FAIL

Pattern :
```
Failed %{WORD:sshd_auth_type} for %{USERNAME:sshd_invalid_user} from %{IP:sshd_client_ip} port %{NUMBER:sshd_port} %{WORD:sshd_protocol}
```

## NAGIOS_EC_LINE_ENABLE_SVC_CHECK

Pattern :
```
%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_ENABLE_SVC_CHECK:nagios_command};%{DATA:nagios_hostname};%{DATA:nagios_service}
```

## NAGIOS_EC_LINE_DISABLE_SVC_CHECK

Pattern :
```
%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_DISABLE_SVC_CHECK:nagios_command};%{DATA:nagios_hostname};%{DATA:nagios_service}
```

## CISCO_REASON

Pattern :
```
Duplicate TCP SYN|Failed to locate egress interface|Invalid transport field|No matching connection|DNS Response|DNS Query|(?:%{WORD}\s*)*
```

## SSHD_CORRUPTED

Pattern :
```
%{SSHD_IDENT_FAIL}|%{SSHD_MAPB_FAIL}|%{SSHD_RMAP_FAIL}|%{SSHD_TOOMANY_AUTH}|%{SSHD_CORRUPT_MAC}|%{SSHD_PACKET_CORRUPT}|%{SSHD_BAD_VERSION}
```

## BACULA_LOG_NO_CONNECT

Pattern :
```
Warning: bsock.c:127 Could not connect to (Client: %{BACULA_HOST:client}|Storage daemon) on %{HOSTNAME}:%{POSINT}. ERR=%{GREEDYDATA:berror}
```

## SSHD_DISCONNECT

Pattern :
```
Received disconnect from %{IP:sshd_client_ip} port %{NUMBER:sshd_port}:%{NUMBER:sshd_disconnect_code}: %{GREEDYDATA:sshd_disconnect_status}
```

## SSHD_MAPB_FAIL

Pattern :
```
Address %{IP:sshd_client_ip} maps to %{HOSTNAME:sshd_client_hostname}, but this does not map back to the address - POSSIBLE BREAK-IN ATTEMPT!
```

## SSHD_TCPWRAP_FAIL2

Pattern :
```
warning: %{DATA:sshd_tcpd_file}, line %{NUMBER}: host name/address mismatch: %{IPORHOST:sshd_client_ip} != %{HOSTNAME:sshd_paranoid_hostname}
```

## MONGO3_LOG

Pattern :
```
%{TIMESTAMP_ISO8601:timestamp} %{MONGO3_SEVERITY:severity} %{MONGO3_COMPONENT:component}%{SPACE}(?:\[%{DATA:context}\])? %{GREEDYDATA:message}
```

## BACULA_LOG_FATAL_CONN

Pattern :
```
Fatal error: bsock.c:133 Unable to connect to (Client: %{BACULA_HOST:client}|Storage daemon) on %{HOSTNAME}:%{POSINT}. ERR=%{GREEDYDATA:berror}
```

## SSHD_TCPWRAP_FAIL4

Pattern :
```
warning: %{DATA:sshd_tcpd_file}, line %{NUMBER}: host name/name mismatch: reverse lookup results in non-FQDN %{HOSTNAME:sshd_paranoid_hostname}
```

## CISCOFW710001_710002_710003_710005_710006

Pattern :
```
%{WORD:protocol} (?:request|access) %{CISCO_ACTION:action} from %{IP:src_ip}/%{INT:src_port} to %{DATA:dst_interface}:%{IP:dst_ip}/%{INT:dst_port}
```

## NAGIOS_PASSIVE_SERVICE_CHECK

Pattern :
```
%{NAGIOS_TYPE_PASSIVE_SERVICE_CHECK:nagios_type}: %{DATA:nagios_hostname};%{DATA:nagios_service};%{DATA:nagios_state};%{GREEDYDATA:nagios_comment}
```

## NAGIOS_SERVICE_FLAPPING_ALERT

Pattern :
```
%{NAGIOS_TYPE_SERVICE_FLAPPING_ALERT:nagios_type}: %{DATA:nagios_hostname};%{DATA:nagios_service};%{DATA:nagios_state};%{GREEDYDATA:nagios_message}
```

## NAGIOS_SERVICE_DOWNTIME_ALERT

Pattern :
```
%{NAGIOS_TYPE_SERVICE_DOWNTIME_ALERT:nagios_type}: %{DATA:nagios_hostname};%{DATA:nagios_service};%{DATA:nagios_state};%{GREEDYDATA:nagios_comment}
```

## TCPDUMP_OUTPUT

Pattern :
```
%{GREEDYDATA:timestamp} IP %{IPORHOST:source_ip}\.%{INT:source_port} > %{IPORHOST:dest_ip}\.%{INT:dest_port}: Flags \[%{GREEDYDATA:tcpflags}\], seq
```

## SSHD_TCPWRAP_FAIL1

Pattern :
```
warning: %{DATA:sshd_tcpd_file}, line %{NUMBER}: can't verify hostname: getaddrinfo\(%{DATA:sshd_paranoid_hostname}, %{DATA:sshd_sa_family}\) failed
```

## SSHD_FAIL_PREAUTH

Pattern :
```
fatal: Unable to negotiate with %{IP:sshd_client_ip} port %{NUMBER:sshd_port}:\s*%{GREEDYDATA:sshd_disconnect_status}? \[%{GREEDYDATA:sshd_privsep}\]
```

## NAGIOS_EC_LINE_ENABLE_SVC_NOTIFICATIONS

Pattern :
```
%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_ENABLE_SVC_NOTIFICATIONS:nagios_command};%{DATA:nagios_hostname};%{GREEDYDATA:nagios_service}
```

## SSHD_TCPWRAP_FAIL3

Pattern :
```
warning: %{DATA:sshd_tcpd_file}, line %{NUMBER}: host name/name mismatch: %{HOSTNAME:sshd_paranoid_hostname_1} != %{HOSTNAME:sshd_paranoid_hostname_2}
```

## NAGIOS_EC_LINE_DISABLE_SVC_NOTIFICATIONS

Pattern :
```
%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_DISABLE_SVC_NOTIFICATIONS:nagios_command};%{DATA:nagios_hostname};%{GREEDYDATA:nagios_service}
```

## NAGIOS_HOST_EVENT_HANDLER

Pattern :
```
%{NAGIOS_TYPE_HOST_EVENT_HANDLER:nagios_type}: %{DATA:nagios_hostname};%{DATA:nagios_state};%{DATA:nagios_statelevel};%{DATA:nagios_event_handler_name}
```

## CISCOFW313001_313004_313008

Pattern :
```
%{CISCO_ACTION:action} %{WORD:protocol} type=%{INT:icmp_type}, code=%{INT:icmp_code} from %{IP:src_ip} on interface %{DATA:interface}( to %{IP:dst_ip})?
```

## BACULA_LOG_END_VOLUME

Pattern :
```
End of medium on Volume \"%{BACULA_VOLUME:volume}\" Bytes=%{BACULA_CAPACITY} Blocks=%{BACULA_CAPACITY} at %{MONTHDAY}-%{MONTH}-%{YEAR} %{HOUR}:%{MINUTE}.
```

## SSHD_SUCCESS

Pattern :
```
Accepted %{WORD:sshd_auth_type} for %{USERNAME:sshd_user} from %{IP:sshd_client_ip} port %{NUMBER:sshd_port} %{WORD:sshd_protocol}: %{GREEDYDATA:sshd_cipher}
```

## SMB_AUTH_FAIL

Pattern :
```
Auth:%{GREEDYDATA} user \[%{DATA:smb_domain}\]\\\[%{DATA:user}\]%{GREEDYDATA} status \[NT_STATUS_NO_SUCH_USER\]%{GREEDYDATA} remote host \[ipv4:%{IP:ip_source}
```

## BACULA_LOG_NEW_MOUNT

Pattern :
```
New volume \"%{BACULA_VOLUME:volume}\" mounted on device \"%{BACULA_DEVICE:device}\" \(%{BACULA_DEVICEPATH}\) at %{MONTHDAY}-%{MONTH}-%{YEAR} %{HOUR}:%{MINUTE}.
```

## NAGIOS_HOST_ALERT

Pattern :
```
%{NAGIOS_TYPE_HOST_ALERT:nagios_type}: %{DATA:nagios_hostname};%{DATA:nagios_state};%{DATA:nagios_statelevel};%{NUMBER:nagios_attempt};%{GREEDYDATA:nagios_message}
```

## NAGIOS_HOST_NOTIFICATION

Pattern :
```
%{NAGIOS_TYPE_HOST_NOTIFICATION:nagios_type}: %{DATA:nagios_notifyname};%{DATA:nagios_hostname};%{DATA:nagios_state};%{DATA:nagios_contact};%{GREEDYDATA:nagios_message}
```

## SYSLOGPAMSESSION

Pattern :
```
%{SYSLOGBASE} %{GREEDYDATA:message}%{WORD:pam_module}\(%{DATA:pam_caller}\): session %{WORD:pam_session_state} for user %{USERNAME:username}(?: by %{GREEDYDATA:pam_by})?
```

## NAGIOS_CURRENT_HOST_STATE

Pattern :
```
%{NAGIOS_TYPE_CURRENT_HOST_STATE:nagios_type}: %{DATA:nagios_hostname};%{DATA:nagios_state};%{DATA:nagios_statetype};%{DATA:nagios_statecode};%{GREEDYDATA:nagios_message}
```

## CISCOFW419002

Pattern :
```
%{CISCO_REASON:reason} from %{DATA:src_interface}:%{IP:src_ip}/%{INT:src_port} to %{DATA:dst_interface}:%{IP:dst_ip}/%{INT:dst_port} with different initial sequence number
```

## IPV4

Pattern :
```
(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))
```

## SSHD_FAI2_PREAUTH

Pattern :
```
fatal: %{GREEDYDATA:sshd_fatal_status}: Connection from %{IP:sshd_client_ip} port %{NUMBER:sshd_port}:\s*%{GREEDYDATA:sshd_disconnect_status}? \[%{GREEDYDATA:sshd_privsep}\]
```

## APACHEERRORPREFIX

Pattern :
```
\[%{APACHEERRORTIME:timestamp}\] \[%{NOTSPACE:apacheseverity}\] (\[pid %{INT}:tid %{INT}\] )?\[client %{IPORHOST:sourcehost}(:%{INT:source_port})?\] (\[client %{IPORHOST}\])?
```

## NAGIOS_SERVICE_EVENT_HANDLER

Pattern :
```
%{NAGIOS_TYPE_SERVICE_EVENT_HANDLER:nagios_type}: %{DATA:nagios_hostname};%{DATA:nagios_service};%{DATA:nagios_state};%{DATA:nagios_statelevel};%{DATA:nagios_event_handler_name}
```

## NAGIOS_EC_LINE_PROCESS_HOST_CHECK_RESULT

Pattern :
```
%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_PROCESS_HOST_CHECK_RESULT:nagios_command};%{DATA:nagios_hostname};%{DATA:nagios_state};%{GREEDYDATA:nagios_check_result}
```

## SSHD_PROBE_LOG

Pattern :
```
%{SSHD_REFUSE_CONN}|%{SSHD_TCPWRAP_FAIL1}|%{SSHD_TCPWRAP_FAIL2}|%{SSHD_TCPWRAP_FAIL3}|%{SSHD_TCPWRAP_FAIL4}|%{SSHD_TCPWRAP_FAIL5}|%{SSHD_FAIL}|%{SSHD_USER_FAIL}|%{SSHD_INVAL_USER}
```

## NAXSI_EXLOG

Pattern :
```
^NAXSI_EXLOG: ip=%{IPORHOST:naxsi_src_ip}&server=%{IPORHOST:naxsi_dst_ip}&uri=%{PATH:http_path}&id=%{INT:naxsi_id}&zone=%{WORD:naxsi_zone}&var_name=%{DATA:naxsi_var_name}&content=
```

## SSHD_RECE_PREAUTH

Pattern :
```
(?:error: |)Received disconnect from %{IP:sshd_client_ip} port %{NUMBER:sshd_port}:%{NUMBER:sshd_disconnect_code}: %{GREEDYDATA:sshd_disconnect_status}? \[%{GREEDYDATA:sshd_privsep}\]
```

## MONTH

Pattern :
```
\bJan(?:uary|uar)?|Feb(?:ruary|ruar)?|M(?:a|ä)?r(?:ch|z)?|Apr(?:il)?|Ma(?:y|i)?|Jun(?:e|i)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|O(?:c|k)?t(?:ober)?|Nov(?:ember)?|De(?:c|z)(?:ember)?\b
```

## CISCOFW419001

Pattern :
```
%{CISCO_ACTION:action} %{WORD:protocol} packet from %{DATA:src_interface}:%{IP:src_ip}/%{INT:src_port} to %{DATA:dst_interface}:%{IP:dst_ip}/%{INT:dst_port}, reason: %{GREEDYDATA:reason}
```

## NAGIOS_SERVICE_ALERT

Pattern :
```
%{NAGIOS_TYPE_SERVICE_ALERT:nagios_type}: %{DATA:nagios_hostname};%{DATA:nagios_service};%{DATA:nagios_state};%{DATA:nagios_statelevel};%{NUMBER:nagios_attempt};%{GREEDYDATA:nagios_message}
```

## CISCOFW106015

Pattern :
```
%{CISCO_ACTION:action} %{WORD:protocol} \(%{DATA:policy_id}\) from %{IP:src_ip}/%{INT:src_port} to %{IP:dst_ip}/%{INT:dst_port} flags %{DATA:tcp_flags}  on interface %{GREEDYDATA:interface}
```

## CISCOFW602303_602304

Pattern :
```
%{WORD:protocol}: An %{CISCO_DIRECTION:direction} %{GREEDYDATA:tunnel_type} SA \(SPI= %{DATA:spi}\) between %{IP:src_ip} and %{IP:dst_ip} \(user= %{DATA:user}\) has been %{CISCO_ACTION:action}
```

## NAGIOS_SERVICE_NOTIFICATION

Pattern :
```
%{NAGIOS_TYPE_SERVICE_NOTIFICATION:nagios_type}: %{DATA:nagios_notifyname};%{DATA:nagios_hostname};%{DATA:nagios_service};%{DATA:nagios_state};%{DATA:nagios_contact};%{GREEDYDATA:nagios_message}
```

## RT_FLOW3

Pattern :
```
%{RT_FLOW_EVENT:event}: session denied %{IP:src-ip}/%{INT:src-port}->%{IP:dst-ip}/%{INT:dst-port} %{DATA:service} %{INT:protocol-id}\(\d\) %{DATA:policy-name} %{DATA:from-zone} %{DATA:to-zone} .*
```

## NAGIOS_CURRENT_SERVICE_STATE

Pattern :
```
%{NAGIOS_TYPE_CURRENT_SERVICE_STATE:nagios_type}: %{DATA:nagios_hostname};%{DATA:nagios_service};%{DATA:nagios_state};%{DATA:nagios_statetype};%{DATA:nagios_statecode};%{GREEDYDATA:nagios_message}
```

## CISCOFW713172

Pattern :
```
Group = %{GREEDYDATA:group}, IP = %{IP:src_ip}, Automatic NAT Detection Status:\s+Remote end\s*%{DATA:is_remote_natted}\s*behind a NAT device\s+This\s+end\s*%{DATA:is_local_natted}\s*behind a NAT device
```

## NAGIOS_EC_LINE_PROCESS_SERVICE_CHECK_RESULT

Pattern :
```
%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_PROCESS_SERVICE_CHECK_RESULT:nagios_command};%{DATA:nagios_hostname};%{DATA:nagios_service};%{DATA:nagios_state};%{GREEDYDATA:nagios_check_result}
```

## CISCOFW402119

Pattern :
```
%{WORD:protocol}: Received an %{WORD:orig_protocol} packet \(SPI= %{DATA:spi}, sequence number= %{DATA:seq_num}\) from %{IP:src_ip} \(user= %{DATA:user}\) to %{IP:dst_ip} that failed anti-replay checking
```

## SSHD_PREAUTH

Pattern :
```
%{SSHD_DISC_PREAUTH}|%{SSHD_RECE_PREAUTH}|%{SSHD_MAXE_PREAUTH}|%{SSHD_DISR_PREAUTH}|%{SSHD_INVA_PREAUTH}|%{SSHD_REST_PREAUTH}|%{SSHD_FAIL_PREAUTH}|%{SSHD_CLOS_PREAUTH}|%{SSHD_FAI2_PREAUTH}|%{SSHD_BADL_PREAUTH}
```

## COMMONAPACHELOG

Pattern :
```
%{IPORHOST:clientip} %{HTTPDUSER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%{NUMBER:bytes}|-)
```

## SSHD_MAXE_PREAUTH

Pattern :
```
error: maximum authentication attempts exceeded for (?:invalid user |)%{USERNAME:sshd_invalid_user} from %{IP:sshd_client_ip} port %{NUMBER:sshd_port} %{WORD:sshd_protocol}\s*(?:\[%{GREEDYDATA:sshd_privsep}\]|)
```

## CISCOFW106001

Pattern :
```
%{CISCO_DIRECTION:direction} %{WORD:protocol} connection %{CISCO_ACTION:action} from %{IP:src_ip}/%{INT:src_port} to %{IP:dst_ip}/%{INT:dst_port} flags %{GREEDYDATA:tcp_flags} on interface %{GREEDYDATA:interface}
```

## LOGLEVEL

Pattern :
```
[Aa]lert|ALERT|[Tt]race|TRACE|[Dd]ebug|DEBUG|[Nn]otice|NOTICE|[Ii]nfo|INFO|[Ww]arn?(?:ing)?|WARN?(?:ING)?|[Ee]rr?(?:or)?|ERR?(?:OR)?|[Cc]rit?(?:ical)?|CRIT?(?:ICAL)?|[Ff]atal|FATAL|[Ss]evere|SEVERE|EMERG(?:ENCY)?|[Ee]merg(?:ency)?
```

## CISCOFW305011

Pattern :
```
%{CISCO_ACTION:action} %{CISCO_XLATE_TYPE:xlate_type} %{WORD:protocol} translation from %{DATA:src_interface}:%{IP:src_ip}(/%{INT:src_port})?(\(%{DATA:src_fwuser}\))? to %{DATA:src_xlated_interface}:%{IP:src_xlated_ip}/%{DATA:src_xlated_port}
```

## MONGO_SLOWQUERY

Pattern :
```
%{WORD} %{MONGO_WORDDASH:database}\.%{MONGO_WORDDASH:collection} %{WORD}: %{MONGO_QUERY:query} %{WORD}:%{NONNEGINT:ntoreturn} %{WORD}:%{NONNEGINT:ntoskip} %{WORD}:%{NONNEGINT:nscanned}.*nreturned:%{NONNEGINT:nreturned}..+ %{POSINT:duration}ms
```

## NAXSI_FMT

Pattern :
```
^NAXSI_FMT: ip=%{IPORHOST:src_ip}&server=%{IPORHOST:target_ip}&uri=%{PATH:http_path}&learning=\d&vers=%{DATA:naxsi_version}&total_processed=\d+&total_blocked=\d+&block=\d+(&cscore\d=%{WORD:score_label}&score\d=%{INT:score})+&zone0=%{WORD:zone}
```

## CISCOFW106014

Pattern :
```
%{CISCO_ACTION:action} %{CISCO_DIRECTION:direction} %{WORD:protocol} src %{DATA:src_interface}:%{IP:src_ip}(\(%{DATA:src_fwuser}\))? dst %{DATA:dst_interface}:%{IP:dst_ip}(\(%{DATA:dst_fwuser}\))? \(type %{INT:icmp_type}, code %{INT:icmp_code}\)
```

## NGINXACCESS

Pattern :
```
%{IPORHOST:remote_addr} - %{NGUSER:remote_user} \[%{HTTPDATE:time_local}\] "%{WORD:method} %{URIPATHPARAM:request} HTTP/%{NUMBER:http_version}" %{NUMBER:status} %{NUMBER:body_bytes_sent} "%{NOTDQUOTE:http_referer}" "%{NOTDQUOTE:http_user_agent}"
```

## EXIM_EXCLUDE_TERMS

Pattern :
```
(Message is frozen|(Start|End) queue run| Warning: | retry time not reached | no (IP address|host name) found for (IP address|host) | unexpected disconnection while reading SMTP command | no immediate delivery: |another process is handling this message)
```

## CISCOFW302020_302021

Pattern :
```
%{CISCO_ACTION:action}(?: %{CISCO_DIRECTION:direction})? %{WORD:protocol} connection for faddr %{IP:dst_ip}/%{INT:icmp_seq_num}(?:\(%{DATA:fwuser}\))? gaddr %{IP:src_xlated_ip}/%{INT:icmp_code_xlated} laddr %{IP:src_ip}/%{INT:icmp_code}( \(%{DATA:user}\))?
```

## CISCOFW106006_106007_106010

Pattern :
```
%{CISCO_ACTION:action} %{CISCO_DIRECTION:direction} %{WORD:protocol} (?:from|src) %{IP:src_ip}/%{INT:src_port}(\(%{DATA:src_fwuser}\))? (?:to|dst) %{IP:dst_ip}/%{INT:dst_port}(\(%{DATA:dst_fwuser}\))? (?:on interface %{DATA:interface}|due to %{CISCO_REASON:reason})
```

## HTTPD24_ERRORLOG

Pattern :
```
\[%{HTTPDERROR_DATE:timestamp}\] \[%{WORD:module}:%{LOGLEVEL:loglevel}\] \[pid %{POSINT:pid}:tid %{NUMBER:tid}\]( \(%{POSINT:proxy_errorcode}\)%{DATA:proxy_errormessage}:)?( \[client %{IPORHOST:client}:%{POSINT:clientport}\])? %{DATA:errorcode}: %{GREEDYDATA:message}
```

## MODSECAPACHEERROR

Pattern :
```
%{MODSECPREFIX} %{MODSECRULEFILE} %{MODSECRULELINE} (?:%{MODSECMATCHOFFSET} )?(?:%{MODSECRULEID} )?(?:%{MODSECRULEREV} )?(?:%{MODSECRULEMSG} )?(?:%{MODSECRULEDATA} )?(?:%{MODSECRULESEVERITY} )?(?:%{MODSECRULEVERS} )?%{MODSECRULETAGS}%{MODSECHOSTNAME} %{MODSECURI} %{MODSECUID}
```

## NAGIOS_EC_LINE_SCHEDULE_HOST_DOWNTIME

Pattern :
```
%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_SCHEDULE_HOST_DOWNTIME:nagios_command};%{DATA:nagios_hostname};%{NUMBER:nagios_start_time};%{NUMBER:nagios_end_time};%{NUMBER:nagios_fixed};%{NUMBER:nagios_trigger_id};%{NUMBER:nagios_duration};%{DATA:author};%{DATA:comment}
```

## SYSLOG5424BASE

Pattern :
```
%{SYSLOG5424PRI}%{NONNEGINT:syslog5424_ver} +(?:%{TIMESTAMP_ISO8601:syslog5424_ts}|-) +(?:%{HOSTNAME:syslog5424_host}|-) +(-|%{SYSLOG5424PRINTASCII:syslog5424_app}) +(-|%{SYSLOG5424PRINTASCII:syslog5424_proc}) +(-|%{SYSLOG5424PRINTASCII:syslog5424_msgid}) +(?:%{SYSLOG5424SD:syslog5424_sd}|-|)
```

## CISCOFW106100_2_3

Pattern :
```
access-list %{NOTSPACE:policy_id} %{CISCO_ACTION:action} %{WORD:protocol} for user '%{DATA:src_fwuser}' %{DATA:src_interface}/%{IP:src_ip}\(%{INT:src_port}\) -> %{DATA:dst_interface}/%{IP:dst_ip}\(%{INT:dst_port}\) hit-cnt %{INT:hit_count} %{CISCO_INTERVAL:interval} \[%{DATA:hashcode1}, %{DATA:hashcode2}\]
```

## CISCOFW106100

Pattern :
```
access-list %{NOTSPACE:policy_id} %{CISCO_ACTION:action} %{WORD:protocol} %{DATA:src_interface}/%{IP:src_ip}\(%{INT:src_port}\)(\(%{DATA:src_fwuser}\))? -> %{DATA:dst_interface}/%{IP:dst_ip}\(%{INT:dst_port}\)(\(%{DATA:src_fwuser}\))? hit-cnt %{INT:hit_count} %{CISCO_INTERVAL:interval} \[%{DATA:hashcode1}, %{DATA:hashcode2}\]
```

## RT_FLOW2

Pattern :
```
%{RT_FLOW_EVENT:event}: session created %{IP:src-ip}/%{INT:src-port}->%{IP:dst-ip}/%{INT:dst-port} %{DATA:service} %{IP:nat-src-ip}/%{INT:nat-src-port}->%{IP:nat-dst-ip}/%{INT:nat-dst-port} %{DATA:src-nat-rule-name} %{DATA:dst-nat-rule-name} %{INT:protocol-id} %{DATA:policy-name} %{DATA:from-zone} %{DATA:to-zone} %{INT:session-id} .*
```

## CISCOFW733100

Pattern :
```
\[\s*%{DATA:drop_type}\s*\] drop %{DATA:drop_rate_id} exceeded. Current burst rate is %{INT:drop_rate_current_burst} per second, max configured rate is %{INT:drop_rate_max_burst}; Current average rate is %{INT:drop_rate_current_avg} per second, max configured rate is %{INT:drop_rate_max_avg}; Cumulative total count is %{INT:drop_total_count}
```

## CISCOFW106023

Pattern :
```
%{CISCO_ACTION:action}( protocol)? %{WORD:protocol} src %{DATA:src_interface}:%{DATA:src_ip}(/%{INT:src_port})?(\(%{DATA:src_fwuser}\))? dst %{DATA:dst_interface}:%{DATA:dst_ip}(/%{INT:dst_port})?(\(%{DATA:dst_fwuser}\))?( \(type %{INT:icmp_type}, code %{INT:icmp_code}\))? by access-group "?%{DATA:policy_id}"? \[%{DATA:hashcode1}, %{DATA:hashcode2}\]
```

## ELB_ACCESS_LOG

Pattern :
```
%{TIMESTAMP_ISO8601:timestamp} %{NOTSPACE:elb} %{IP:clientip}:%{INT:clientport:int} (?:(%{IP:backendip}:?:%{INT:backendport:int})|-) %{NUMBER:request_processing_time:float} %{NUMBER:backend_processing_time:float} %{NUMBER:response_processing_time:float} %{INT:response:int} %{INT:backend_response:int} %{INT:received_bytes:int} %{INT:bytes:int} "%{ELB_REQUEST_LINE}"
```

## MODSECRULETAGS

Pattern :
```
(?:\[tag %{QUOTEDSTRING:ruletag0}\] )?(?:\[tag %{QUOTEDSTRING:ruletag1}\] )?(?:\[tag %{QUOTEDSTRING:ruletag2}\] )?(?:\[tag %{QUOTEDSTRING:ruletag3}\] )?(?:\[tag %{QUOTEDSTRING:ruletag4}\] )?(?:\[tag %{QUOTEDSTRING:ruletag5}\] )?(?:\[tag %{QUOTEDSTRING:ruletag6}\] )?(?:\[tag %{QUOTEDSTRING:ruletag7}\] )?(?:\[tag %{QUOTEDSTRING:ruletag8}\] )?(?:\[tag %{QUOTEDSTRING:ruletag9}\] )?(?:\[tag %{QUOTEDSTRING}\] )*
```

## RT_FLOW1

Pattern :
```
%{RT_FLOW_EVENT:event}: %{GREEDYDATA:close-reason}: %{IP:src-ip}/%{INT:src-port}->%{IP:dst-ip}/%{INT:dst-port} %{DATA:service} %{IP:nat-src-ip}/%{INT:nat-src-port}->%{IP:nat-dst-ip}/%{INT:nat-dst-port} %{DATA:src-nat-rule-name} %{DATA:dst-nat-rule-name} %{INT:protocol-id} %{DATA:policy-name} %{DATA:from-zone} %{DATA:to-zone} %{INT:session-id} \d+\(%{DATA:sent}\) \d+\(%{DATA:received}\) %{INT:elapsed-time} .*
```

## BRO_CONN

Pattern :
```
%{NUMBER:ts}\t%{NOTSPACE:uid}\t%{IP:orig_h}\t%{INT:orig_p}\t%{IP:resp_h}\t%{INT:resp_p}\t%{WORD:proto}\t%{GREEDYDATA:service}\t%{NUMBER:duration}\t%{NUMBER:orig_bytes}\t%{NUMBER:resp_bytes}\t%{GREEDYDATA:conn_state}\t%{GREEDYDATA:local_orig}\t%{GREEDYDATA:missed_bytes}\t%{GREEDYDATA:history}\t%{GREEDYDATA:orig_pkts}\t%{GREEDYDATA:orig_ip_bytes}\t%{GREEDYDATA:resp_pkts}\t%{GREEDYDATA:resp_ip_bytes}\t%{GREEDYDATA:tunnel_parents}
```

## S3_ACCESS_LOG

Pattern :
```
%{WORD:owner} %{NOTSPACE:bucket} \[%{HTTPDATE:timestamp}\] %{IP:clientip} %{NOTSPACE:requester} %{NOTSPACE:request_id} %{NOTSPACE:operation} %{NOTSPACE:key} (?:"%{S3_REQUEST_LINE}"|-) (?:%{INT:response:int}|-) (?:-|%{NOTSPACE:error_code}) (?:%{INT:bytes:int}|-) (?:%{INT:object_size:int}|-) (?:%{INT:request_time_ms:int}|-) (?:%{INT:turnaround_time_ms:int}|-) (?:%{QS:referrer}|-) (?:"?%{QS:agent}"?|-) (?:-|%{NOTSPACE:version_id})
```

## BRO_DNS

Pattern :
```
%{NUMBER:ts}\t%{NOTSPACE:uid}\t%{IP:orig_h}\t%{INT:orig_p}\t%{IP:resp_h}\t%{INT:resp_p}\t%{WORD:proto}\t%{INT:trans_id}\t%{GREEDYDATA:query}\t%{GREEDYDATA:qclass}\t%{GREEDYDATA:qclass_name}\t%{GREEDYDATA:qtype}\t%{GREEDYDATA:qtype_name}\t%{GREEDYDATA:rcode}\t%{GREEDYDATA:rcode_name}\t%{GREEDYDATA:AA}\t%{GREEDYDATA:TC}\t%{GREEDYDATA:RD}\t%{GREEDYDATA:RA}\t%{GREEDYDATA:Z}\t%{GREEDYDATA:answers}\t%{GREEDYDATA:TTLs}\t%{GREEDYDATA:rejected}
```

## CISCOFW302013_302014_302015_302016

Pattern :
```
%{CISCO_ACTION:action}(?: %{CISCO_DIRECTION:direction})? %{WORD:protocol} connection %{INT:connection_id} for %{DATA:src_interface}:%{IP:src_ip}/%{INT:src_port}( \(%{IP:src_mapped_ip}/%{INT:src_mapped_port}\))?(\(%{DATA:src_fwuser}\))? to %{DATA:dst_interface}:%{IP:dst_ip}/%{INT:dst_port}( \(%{IP:dst_mapped_ip}/%{INT:dst_mapped_port}\))?(\(%{DATA:dst_fwuser}\))?( duration %{TIME:duration} bytes %{INT:bytes})?(?: %{CISCO_REASON:reason})?( \(%{DATA:user}\))?
```

## SHOREWALL

Pattern :
```
(%{SYSLOGTIMESTAMP:timestamp}) (%{WORD:nf_host}) kernel:.*Shorewall:(%{WORD:nf_action1})?:(%{WORD:nf_action2})?.*IN=(%{USERNAME:nf_in_interface})?.*(OUT= *MAC=(%{COMMONMAC:nf_dst_mac}):(%{COMMONMAC:nf_src_mac})?|OUT=%{USERNAME:nf_out_interface}).*SRC=(%{IPV4:nf_src_ip}).*DST=(%{IPV4:nf_dst_ip}).*LEN=(%{WORD:nf_len}).*?TOS=(%{WORD:nf_tos}).*?PREC=(%{WORD:nf_prec}).*?TTL=(%{INT:nf_ttl}).*?ID=(%{INT:nf_id}).*?PROTO=(%{WORD:nf_protocol}).*?SPT=(%{INT:nf_src_port}?.*DPT=%{INT:nf_dst_port}?.*)
```

## HAPROXYTCP

Pattern :
```
(?:%{SYSLOGTIMESTAMP:syslog_timestamp}|%{TIMESTAMP_ISO8601:timestamp8601}) %{IPORHOST:syslog_server} %{SYSLOGPROG}: %{IP:client_ip}:%{INT:client_port} \[%{HAPROXYDATE:accept_date}\] %{NOTSPACE:frontend_name} %{NOTSPACE:backend_name}/%{NOTSPACE:server_name} %{INT:time_queue}/%{INT:time_backend_connect}/%{NOTSPACE:time_duration} %{NOTSPACE:bytes_read} %{NOTSPACE:termination_state} %{INT:actconn}/%{INT:feconn}/%{INT:beconn}/%{INT:srvconn}/%{NOTSPACE:retries} %{INT:srv_queue}/%{INT:backend_queue}
```

## CISCOFW313005

Pattern :
```
%{CISCO_REASON:reason} for %{WORD:protocol} error message: %{WORD:err_protocol} src %{DATA:err_src_interface}:%{IP:err_src_ip}(\(%{DATA:err_src_fwuser}\))? dst %{DATA:err_dst_interface}:%{IP:err_dst_ip}(\(%{DATA:err_dst_fwuser}\))? \(type %{INT:err_icmp_type}, code %{INT:err_icmp_code}\) on %{DATA:interface} interface\.  Original IP payload: %{WORD:protocol} src %{IP:orig_src_ip}/%{INT:orig_src_port}(\(%{DATA:orig_src_fwuser}\))? dst %{IP:orig_dst_ip}/%{INT:orig_dst_port}(\(%{DATA:orig_dst_fwuser}\))?
```

## BRO_FILES

Pattern :
```
%{NUMBER:ts}\t%{NOTSPACE:fuid}\t%{IP:tx_hosts}\t%{IP:rx_hosts}\t%{NOTSPACE:conn_uids}\t%{GREEDYDATA:source}\t%{GREEDYDATA:depth}\t%{GREEDYDATA:analyzers}\t%{GREEDYDATA:mime_type}\t%{GREEDYDATA:filename}\t%{GREEDYDATA:duration}\t%{GREEDYDATA:local_orig}\t%{GREEDYDATA:is_orig}\t%{GREEDYDATA:seen_bytes}\t%{GREEDYDATA:total_bytes}\t%{GREEDYDATA:missing_bytes}\t%{GREEDYDATA:overflow_bytes}\t%{GREEDYDATA:timedout}\t%{GREEDYDATA:parent_fuid}\t%{GREEDYDATA:md5}\t%{GREEDYDATA:sha1}\t%{GREEDYDATA:sha256}\t%{GREEDYDATA:extracted}
```

## BRO_HTTP

Pattern :
```
%{NUMBER:ts}\t%{NOTSPACE:uid}\t%{IP:orig_h}\t%{INT:orig_p}\t%{IP:resp_h}\t%{INT:resp_p}\t%{INT:trans_depth}\t%{GREEDYDATA:method}\t%{GREEDYDATA:domain}\t%{GREEDYDATA:uri}\t%{GREEDYDATA:referrer}\t%{GREEDYDATA:user_agent}\t%{NUMBER:request_body_len}\t%{NUMBER:response_body_len}\t%{GREEDYDATA:status_code}\t%{GREEDYDATA:status_msg}\t%{GREEDYDATA:info_code}\t%{GREEDYDATA:info_msg}\t%{GREEDYDATA:filename}\t%{GREEDYDATA:bro_tags}\t%{GREEDYDATA:username}\t%{GREEDYDATA:password}\t%{GREEDYDATA:proxied}\t%{GREEDYDATA:orig_fuids}\t%{GREEDYDATA:orig_mime_types}\t%{GREEDYDATA:resp_fuids}\t%{GREEDYDATA:resp_mime_types}
```

## NETSCREENSESSIONLOG

Pattern :
```
%{SYSLOGTIMESTAMP:date} %{IPORHOST:device} %{IPORHOST}: NetScreen device_id=%{WORD:device_id}%{DATA}: start_time=%{QUOTEDSTRING:start_time} duration=%{INT:duration} policy_id=%{INT:policy_id} service=%{DATA:service} proto=%{INT:proto} src zone=%{WORD:src_zone} dst zone=%{WORD:dst_zone} action=%{WORD:action} sent=%{INT:sent} rcvd=%{INT:rcvd} src=%{IPORHOST:src_ip} dst=%{IPORHOST:dst_ip} src_port=%{INT:src_port} dst_port=%{INT:dst_port} src-xlated ip=%{IPORHOST:src_xlated_ip} port=%{INT:src_xlated_port} dst-xlated ip=%{IPORHOST:dst_xlated_ip} port=%{INT:dst_xlated_port} session_id=%{INT:session_id} reason=%{GREEDYDATA:reason}
```

## HAPROXYHTTPBASE

Pattern :
```
%{IP:client_ip}:%{INT:client_port} \[%{HAPROXYDATE:accept_date}\] %{NOTSPACE:frontend_name} %{NOTSPACE:backend_name}/%{NOTSPACE:server_name} %{INT:time_request}/%{INT:time_queue}/%{INT:time_backend_connect}/%{INT:time_backend_response}/%{NOTSPACE:time_duration} %{INT:http_status_code} %{NOTSPACE:bytes_read} %{DATA:captured_request_cookie} %{DATA:captured_response_cookie} %{NOTSPACE:termination_state} %{INT:actconn}/%{INT:feconn}/%{INT:beconn}/%{INT:srvconn}/%{NOTSPACE:retries} %{INT:srv_queue}/%{INT:backend_queue} (\\{\%\{HAPROXYCAPTUREDREQUESTHEADERS}\})?( )?(\\{\%\{HAPROXYCAPTUREDRESPONSEHEADERS}\})?( )?"(<BADREQ>|(%{WORD:http_verb} (%{URIPROTO:http_proto}://)?(?:%{USER:http_user}(?::[^@]*)?@)?(?:%{URIHOST:http_host})?(?:%{URIPATHPARAM:http_request})?( HTTP/%{NUMBER:http_version})?))?"
```

## BACULA_LOGLINE

Pattern :
```
%{BACULA_TIMESTAMP:bts} %{BACULA_HOST:hostname} JobId %{INT:jobid}: (%{BACULA_LOG_MAX_CAPACITY}|%{BACULA_LOG_END_VOLUME}|%{BACULA_LOG_NEW_VOLUME}|%{BACULA_LOG_NEW_LABEL}|%{BACULA_LOG_WROTE_LABEL}|%{BACULA_LOG_NEW_MOUNT}|%{BACULA_LOG_NOOPEN}|%{BACULA_LOG_NOOPENDIR}|%{BACULA_LOG_NOSTAT}|%{BACULA_LOG_NOJOBS}|%{BACULA_LOG_ALL_RECORDS_PRUNED}|%{BACULA_LOG_BEGIN_PRUNE_JOBS}|%{BACULA_LOG_BEGIN_PRUNE_FILES}|%{BACULA_LOG_PRUNED_JOBS}|%{BACULA_LOG_PRUNED_FILES}|%{BACULA_LOG_ENDPRUNE}|%{BACULA_LOG_STARTJOB}|%{BACULA_LOG_STARTRESTORE}|%{BACULA_LOG_USEDEVICE}|%{BACULA_LOG_DIFF_FS}|%{BACULA_LOG_JOBEND}|%{BACULA_LOG_NOPRUNE_JOBS}|%{BACULA_LOG_NOPRUNE_FILES}|%{BACULA_LOG_VOLUME_PREVWRITTEN}|%{BACULA_LOG_READYAPPEND}|%{BACULA_LOG_CANCELLING}|%{BACULA_LOG_MARKCANCEL}|%{BACULA_LOG_CLIENT_RBJ}|%{BACULA_LOG_VSS}|%{BACULA_LOG_MAXSTART}|%{BACULA_LOG_DUPLICATE}|%{BACULA_LOG_NOJOBSTAT}|%{BACULA_LOG_FATAL_CONN}|%{BACULA_LOG_NO_CONNECT}|%{BACULA_LOG_NO_AUTH}|%{BACULA_LOG_NOSUIT}|%{BACULA_LOG_JOB}|%{BACULA_LOG_NOPRIOR})
```

## NAGIOSLOGLINE

Pattern :
```
%{NAGIOSTIME} (?:%{NAGIOS_WARNING}|%{NAGIOS_CURRENT_SERVICE_STATE}|%{NAGIOS_CURRENT_HOST_STATE}|%{NAGIOS_SERVICE_NOTIFICATION}|%{NAGIOS_HOST_NOTIFICATION}|%{NAGIOS_SERVICE_ALERT}|%{NAGIOS_HOST_ALERT}|%{NAGIOS_SERVICE_FLAPPING_ALERT}|%{NAGIOS_HOST_FLAPPING_ALERT}|%{NAGIOS_SERVICE_DOWNTIME_ALERT}|%{NAGIOS_HOST_DOWNTIME_ALERT}|%{NAGIOS_PASSIVE_SERVICE_CHECK}|%{NAGIOS_PASSIVE_HOST_CHECK}|%{NAGIOS_SERVICE_EVENT_HANDLER}|%{NAGIOS_HOST_EVENT_HANDLER}|%{NAGIOS_TIMEPERIOD_TRANSITION}|%{NAGIOS_EC_LINE_DISABLE_SVC_CHECK}|%{NAGIOS_EC_LINE_ENABLE_SVC_CHECK}|%{NAGIOS_EC_LINE_DISABLE_HOST_CHECK}|%{NAGIOS_EC_LINE_ENABLE_HOST_CHECK}|%{NAGIOS_EC_LINE_PROCESS_HOST_CHECK_RESULT}|%{NAGIOS_EC_LINE_PROCESS_SERVICE_CHECK_RESULT}|%{NAGIOS_EC_LINE_SCHEDULE_HOST_DOWNTIME}|%{NAGIOS_EC_LINE_DISABLE_HOST_SVC_NOTIFICATIONS}|%{NAGIOS_EC_LINE_ENABLE_HOST_SVC_NOTIFICATIONS}|%{NAGIOS_EC_LINE_DISABLE_HOST_NOTIFICATIONS}|%{NAGIOS_EC_LINE_ENABLE_HOST_NOTIFICATIONS}|%{NAGIOS_EC_LINE_DISABLE_SVC_NOTIFICATIONS}|%{NAGIOS_EC_LINE_ENABLE_SVC_NOTIFICATIONS})
```

## IPV6

Pattern :
```
((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?
```


# Documentation generation
This documentation is generated by `pkg/parser` : `GO_WANT_TEST_DOC=1 go test -run TestGeneratePatternsDoc`
