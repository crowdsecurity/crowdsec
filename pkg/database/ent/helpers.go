package ent

func (m *Machine) GetOsname() string {
	return m.Osname
}

func (b *Bouncer) GetOsname() string {
	return b.Osname
}

func (m *Machine) GetOsversion() string {
	return m.Osversion
}

func (b *Bouncer) GetOsversion() string {
	return b.Osversion
}

func (m *Machine) GetFeatureflags() string {
	return m.Featureflags
}

func (b *Bouncer) GetFeatureflags() string {
	return b.Featureflags
}
