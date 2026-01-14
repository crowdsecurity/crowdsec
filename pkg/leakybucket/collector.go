package leakybucket

import (
	"sync"
	
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type PourCollector struct {
	mu sync.Mutex
	m  map[string][]pipeline.Event
}

func NewPourCollector() *PourCollector {
	return &PourCollector{
		m: make(map[string][]pipeline.Event),
	}
}

func (c *PourCollector) Add(key string, evt pipeline.Event) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.m[key] = append(c.m[key], evt)
	c.mu.Unlock()
}

// Snapshot returns a shallow copy of the map and slices.
// The caller must not mutate the events.
func (c *PourCollector) Snapshot() map[string][]pipeline.Event {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make(map[string][]pipeline.Event, len(c.m))
	for k, v := range c.m {
		tmp := make([]pipeline.Event, len(v))
		copy(tmp, v)
		out[k] = tmp
	}
	return out
}

func (c *PourCollector) DumpYAML() ([]byte, error) {
	if c == nil {
		return nil, nil
	}

	return yaml.Marshal(c.Snapshot())
}
