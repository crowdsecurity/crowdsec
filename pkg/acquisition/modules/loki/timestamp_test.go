package loki

import (
	"testing"
	"time"

	"gopkg.in/yaml.v2"
)

func TestTimestampFail(t *testing.T) {
	var tt timestamp
	err := yaml.Unmarshal([]byte("plop"), tt)
	if err == nil {
		t.Fail()
	}
}

func TestTimestampTime(t *testing.T) {
	var tt timestamp
	const ts string = "2022-06-14T12:56:39+02:00"
	err := yaml.Unmarshal([]byte(ts), &tt)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if ts != time.Time(tt).Format(time.RFC3339) {
		t.Fail()
	}
}

func TestTimestampDuration(t *testing.T) {
	var tt timestamp
	err := yaml.Unmarshal([]byte("3h"), &tt)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	d, err := time.ParseDuration("3h")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	z := time.Now().Add(-d)
	if z.Round(time.Second) != time.Time(tt).Round(time.Second) {
		t.Fail()
	}
}
