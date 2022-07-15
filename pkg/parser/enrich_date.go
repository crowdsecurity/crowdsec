package parser

import (
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
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
			log.Warningf("Failed marshaling '%v'", t)
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

func ParseDate(in string, p *types.Event, x interface{}) (map[string]string, error) {

	var ret map[string]string = make(map[string]string)
	var strDate string
	var parsedDate time.Time

	//log.Printf("received events : %+v", p.Parsed)
	if v, ok := p.Parsed["DateFormat"]; ok && v != "" {
		strDate, parsedDate = parseDateWithFormat(in, v)
		if !parsedDate.IsZero() {
			ret["MarshaledTime"] = strDate
			return ret, nil
		}
	}
	strDate, parsedDate = GenDateParse(in)
	if !parsedDate.IsZero() {
		ret["MarshaledTime"] = strDate
		return ret, nil
	}

	now := time.Now().UTC()
	retstr, err := now.MarshalText()
	if err != nil {
		log.Warning("Failed marshaling current time")
		return ret, err
	}
	ret["MarshaledTime"] = string(retstr)

	return ret, nil
}

func parseDateInit(cfg map[string]string) (interface{}, error) {
	return nil, nil
}
