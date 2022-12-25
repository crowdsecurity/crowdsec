package fflag

var Crowdsec = FeatureRegister{EnvPrefix: "CROWDSEC_FEATURE_"}

var CscliSetup = &Feature{Name: "cscli_setup"}

func RegisterAllFeatures() error {
	err := Crowdsec.RegisterFeature(CscliSetup)
	if err != nil {
		return err
	}

	return nil
}
