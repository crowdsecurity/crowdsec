package dockeracquisition

import (
	"slices"
	"strings"
)

func parseLabels(labels map[string]string) map[string]any {
	result := make(map[string]any)
	for key, value := range labels {
		parseKeyToMap(result, key, value)
	}
	return result
}

func parseKeyToMap(m map[string]any, key string, value string) {
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
		if _, ok := m[parts[i]]; !ok {
			m[parts[i]] = make(map[string]any)
		}
		m = m[parts[i]].(map[string]any)
	}
	m[parts[len(parts)-1]] = value
}
