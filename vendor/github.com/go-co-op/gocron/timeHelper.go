package gocron

import "time"

var _ timeWrapper = (*trueTime)(nil)

type timeWrapper interface {
	Now(*time.Location) time.Time
	Unix(int64, int64) time.Time
	Sleep(time.Duration)
}

type trueTime struct{}

func (t *trueTime) Now(location *time.Location) time.Time {
	return time.Now().In(location)
}

func (t *trueTime) Unix(sec int64, nsec int64) time.Time {
	return time.Unix(sec, nsec)
}

func (t *trueTime) Sleep(d time.Duration) {
	time.Sleep(d)
}
