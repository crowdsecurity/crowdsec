package dockeracquisition

import (
	"slices"
	"strings"
)

func parseLabels(labels map[string]string) map[string]interface{} {
	result := make(map[string]interface{})

	// Iterate in sorted key order so the result is deterministic. Go map
	// iteration order is random, and when a leaf and a branch collide under the
	// same key (e.g. crowdsec.enable and crowdsec.enable.foo) only one can win;
	// sorting means the shorter, less specific key is always applied first and
	// then overwritten by the more specific one, instead of the winner being
	// decided at random from run to run.
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	for _, key := range keys {
		parseKeyToMap(result, key, labels[key])
	}

	return result
}

func parseKeyToMap(m map[string]interface{}, key string, value string) {
	if !strings.HasPrefix(key, "crowdsec") {
		return
	}
	parts := strings.Split(key, ".")

	if len(parts) < 2 || parts[0] != "crowdsec" {
		return
	}

	if slices.Contains(parts, "") {
		return
	}

	for i := 1; i < len(parts)-1; i++ {
		next, ok := m[parts[i]].(map[string]interface{})
		if !ok {
			// The key is absent, or a leaf value (e.g. a sibling label like
			// crowdsec.enable=true) is already stored here. Replace it with a
			// nested map instead of panicking on the type assertion.
			next = make(map[string]interface{})
			m[parts[i]] = next
		}
		m = next
	}
	m[parts[len(parts)-1]] = value
}
