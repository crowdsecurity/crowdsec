package logging

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type countingHook struct {
	levels []logrus.Level
	fired  int
}

func (h *countingHook) Levels() []logrus.Level { return h.levels }

func (h *countingHook) Fire(*logrus.Entry) error {
	h.fired++
	return nil
}

func TestSubLoggerFiresHooksOnce(t *testing.T) {
	tests := []struct {
		name   string
		levels []logrus.Level
	}{
		{name: "all levels", levels: logrus.AllLevels},
		{name: "single level", levels: []logrus.Level{logrus.InfoLevel}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hook := &countingHook{levels: tc.levels}

			base := logrus.New()
			base.AddHook(hook)

			SubLogger(base, "test", logrus.InfoLevel).Info("hello")

			require.Equal(t, 1, hook.fired)
		})
	}
}
