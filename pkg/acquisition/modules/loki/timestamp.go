package loki

import (
	"fmt"
	"time"
)

type timestamp time.Time

func (t *timestamp) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var tt time.Time
	err := unmarshal(&tt)
	if err == nil {
		*t = timestamp(tt)
		return nil
	}
	var d time.Duration
	err = unmarshal(&d)
	if err == nil {
		*t = timestamp(time.Now().Add(-d))
		fmt.Println("t", time.Time(*t).Format(time.RFC3339))
		return nil
	}
	return err
}

func (t *timestamp) IsZero() bool {
	return time.Time(*t).IsZero()
}
