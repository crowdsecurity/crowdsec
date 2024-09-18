package dockeracquisition

import (
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

	for i := range parts {
		if parts[i] == "" {
			return
		}
	}

	for i := 1; i < len(parts)-1; i++ {
		if _, ok := m[parts[i]]; !ok {
			m[parts[i]] = make(map[string]interface{})
		}
		m = m[parts[i]].(map[string]interface{})
	}
	m[parts[len(parts)-1]] = value
}
