package gocron

import "time"

var _ TimeWrapper = (*trueTime)(nil)

// TimeWrapper is an interface that wraps the Now, Sleep, and Unix methods of the time package.
// This allows the library and users to mock the time package for testing.
type TimeWrapper interface {
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

// afterFunc proxies the time.AfterFunc function.
// This allows it to be mocked for testing.
func afterFunc(d time.Duration, f func()) *time.Timer {
	return time.AfterFunc(d, f)
}
