package metrics

import (
	"io"

	"github.com/jedib0t/go-pretty/v6/text"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
)

func (s statBucket) Description() (string, string) {
	return "Scenario Metrics",
		`Measure events in different scenarios. Current count is the number of buckets during metrics collection. ` +
			`Overflows are past event-producing buckets, while Expired are the ones that didn’t receive enough events to Overflow.`
}

func (s statBucket) Process(bucket, metric string, val int) {
	if _, ok := s[bucket]; !ok {
		s[bucket] = make(map[string]int)
	}

	s[bucket][metric] += val
}

func (s statBucket) Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool) {
	t := cstable.New(out, wantColor)
	t.SetRowLines(false)
	t.SetHeaders("Scenario", "Current Count", "Overflows", "Instantiated", "Poured", "Expired")
	t.SetAlignment(text.AlignLeft, text.AlignLeft, text.AlignLeft, text.AlignLeft, text.AlignLeft, text.AlignLeft)

	keys := []string{"curr_count", "overflow", "instantiation", "pour", "underflow"}

	if numRows, err := metricsToTable(t, s, keys, noUnit); err != nil {
		log.Warningf("while collecting scenario stats: %s", err)
	} else if numRows > 0 || showEmpty {
		title, _ := s.Description()
		cstable.RenderTitle(out, "\n"+title+":")
		t.Render()
	}
}
