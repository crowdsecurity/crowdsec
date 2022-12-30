package fflag

var Crowdsec = FeatureRegister{EnvPrefix: "CROWDSEC_FEATURE_"}

var CscliSetup = &Feature{Name: "cscli_setup"}
var DisableHttpRetryBackoff = &Feature{Name: "disable_http_retry_backoff", Description: "Disable http retry backoff"}

func RegisterAllFeatures() error {
	err := Crowdsec.RegisterFeature(CscliSetup)
	if err != nil {
		return err
	}
	err = Crowdsec.RegisterFeature(DisableHttpRetryBackoff)
	if err != nil {
		return err
	}

	return nil
}
