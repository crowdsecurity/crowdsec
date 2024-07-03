package ent

import (
	"strings"
)


// XXX: we can DRY here

func (m *Machine) GetOSNameAndVersion() string {
	ret := m.Osname
	if m.Osversion != "" {
		if ret != "" {
			ret += "/"
		}
		ret += m.Osversion
	}
	if ret == "" {
		return "?"
	}
	return ret
}

func (b *Bouncer) GetOSNameAndVersion() string {
	ret := b.Osname
	if b.Osversion != "" {
		if ret != "" {
			ret += "/"
		}
		ret += b.Osversion
	}
	if ret == "" {
		return "?"
	}
	return ret
}

func (m *Machine) GetFeatureFlagList() []string {
	if m.Featureflags == "" {
		return nil
	}
	return strings.Split(m.Featureflags, ",")
}

func (b *Bouncer) GetFeatureFlagList() []string {
	if b.Featureflags == "" {
		return nil
	}
	return strings.Split(b.Featureflags, ",")
}
