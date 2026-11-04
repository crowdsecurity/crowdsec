package pipeline

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQueueGrowsOnDemand(t *testing.T) {
	q := NewQueue(150)
	require.Zero(t, cap(q.Queue))

	for i := range 200 {
		q.Add(Event{StrTime: strconv.Itoa(i)})
	}

	require.Len(t, q.GetQueue(), 151)
	assert.Equal(t, "49", q.GetQueue()[0].StrTime)
	assert.Equal(t, "199", q.GetQueue()[150].StrTime)
}
