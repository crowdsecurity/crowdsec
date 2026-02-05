package clientinfo

import (
	"strings"
)

type featureflagProvider interface {
	GetFeatureflags() string
}

type osProvider interface {
	GetOsname() string
	GetOsversion() string
}

func GetOSNameAndVersion(o osProvider) string {
	ret := o.GetOsname()
	if o.GetOsversion() != "" {
		if ret != "" {
			ret += "/"
		}

		ret += o.GetOsversion()
	}

	if ret == "" {
		return "?"
	}

	return ret
}

func GetFeatureFlagList(o featureflagProvider) []string {
	if o.GetFeatureflags() == "" {
		return nil
	}

	return strings.Split(o.GetFeatureflags(), ",")
}
