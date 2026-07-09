package dockeracquisition

import (
	"slices"
	"strings"
)

func parseLabels(labels map[string]string) map[string]interface{} {
	result := make(map[string]interface{})
	for key, value := range labels {
		parseKeyToMap(result, key, value)
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
