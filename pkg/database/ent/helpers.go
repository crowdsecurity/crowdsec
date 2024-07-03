package ent

func (m *Machine) GetOSNameAndVersion() string {
	ret := m.Osname
	if m.Osversion != "" {
		ret += "/" + m.Osversion
	}
	return ret
}

func (b *Bouncer) GetOSNameAndVersion() string {
	ret := b.Osname
	if b.Osversion != "" {
		ret += "/" + b.Osversion
	}
	return ret
}
