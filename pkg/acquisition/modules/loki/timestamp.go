package loki

import (
	"time"
)

type timestamp time.Time

func (t *timestamp) UnmarshalYAML(unmarshal func(any) error) error {
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
		return nil
	}

	return err
}

func (t *timestamp) IsZero() bool {
	return time.Time(*t).IsZero()
}
