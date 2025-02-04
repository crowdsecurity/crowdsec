package parser

import (
	"time"

	log "github.com/sirupsen/logrus"

	expr "github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func parseDateWithFormat(date, format string) (string, time.Time) {
	t, err := time.Parse(format, date)
	if err == nil && !t.IsZero() {
		//if the year isn't set, set it to current date :)
		if t.Year() == 0 {
			t = t.AddDate(time.Now().UTC().Year(), 0, 0)
		}
		retstr, err := t.MarshalText()
		if err != nil {
			log.Warningf("Failed to serialize '%v'", t)
			return "", time.Time{}
		}
		return string(retstr), t
	}
	return "", time.Time{}
}

func GenDateParse(date string) (string, time.Time) {
	var (
		layouts = [...]string{
			time.RFC3339,
			"02/Jan/2006:15:04:05 -0700",
			"Mon Jan 2 15:04:05 2006",
			"02-Jan-2006 15:04:05 europe/paris",
			"01/02/2006 15:04:05",
			"2006-01-02 15:04:05.999999999 -0700 MST",
			"Jan  2 15:04:05",
			"Mon Jan 02 15:04:05.000000 2006",
			"2006-01-02T15:04:05Z07:00",
			"2006/01/02",
			"2006/01/02 15:04",
			"2006-01-02",
			"2006-01-02 15:04",
			"2006/01/02 15:04:05",
			"2006-01-02 15:04:05",
			"2006-01-02T15:04:05",
		}
	)

	for _, dateFormat := range layouts {
		retstr, parsedDate := parseDateWithFormat(date, dateFormat)
		if !parsedDate.IsZero() {
			return retstr, parsedDate
		}
	}
	return "", time.Time{}
}

func ParseDate(in string, p *types.Event, plog *log.Entry) (map[string]string, error) {

	var ret = make(map[string]string)
	var strDate string
	var parsedDate time.Time
	if in != "" {
		if p.StrTimeFormat != "" {
			strDate, parsedDate = parseDateWithFormat(in, p.StrTimeFormat)
			if !parsedDate.IsZero() {
				ret["MarshaledTime"] = strDate
				//In time machine, we take the time parsed from the event. In live mode, we keep the timestamp collected at acquisition
				if p.ExpectMode == types.TIMEMACHINE {
					p.Time = parsedDate
				}
				return ret, nil
			}
			plog.Debugf("unable to parse '%s' with layout '%s'", in, p.StrTimeFormat)
		}
		strDate, parsedDate = GenDateParse(in)
		if !parsedDate.IsZero() {
			ret["MarshaledTime"] = strDate
			//In time machine, we take the time parsed from the event. In live mode, we keep the timestamp collected at acquisition
			if p.ExpectMode == types.TIMEMACHINE {
				p.Time = parsedDate
			}
			return ret, nil
		}
		timeobj, err := expr.ParseUnixTime(in)
		if err == nil {
			ret["MarshaledTime"] = timeobj.(time.Time).Format(time.RFC3339)
			//In time machine, we take the time parsed from the event. In live mode, we keep the timestamp collected at acquisition
			if p.ExpectMode == types.TIMEMACHINE {
				p.Time = timeobj.(time.Time)
			}
			return ret, nil
		}

	}
	plog.Debugf("no suitable date format found for '%s', falling back to now", in)
	now := time.Now().UTC()
	retstr, err := now.MarshalText()
	if err != nil {
		plog.Warning("Failed to serialize current time")
		return ret, err
	}
	ret["MarshaledTime"] = string(retstr)

	return ret, nil
}
