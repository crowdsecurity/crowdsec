package fflag

var Crowdsec = FeatureRegister{EnvPrefix: "CROWDSEC_FEATURE_"}

var CscliSetup = &Feature{Name: "cscli_setup", Description: "Enable cscli setup command (service detection)"}
var DisableHttpRetryBackoff = &Feature{Name: "disable_http_retry_backoff", Description: "Disable http retry backoff"}
var ChunkedDecisionsStream = &Feature{Name: "chunked_decisions_stream", Description: "Enable chunked decisions stream"}
var PapiClient = &Feature{Name: "papi_client", Description: "Enable Polling API client"}
var Re2Support = &Feature{Name: "re2_support", Description: "Enable RE2 support for GROK patterns"}

func RegisterAllFeatures() error {
	err := Crowdsec.RegisterFeature(CscliSetup)
	if err != nil {
		return err
	}
	err = Crowdsec.RegisterFeature(DisableHttpRetryBackoff)
	if err != nil {
		return err
	}
	err = Crowdsec.RegisterFeature(ChunkedDecisionsStream)
	if err != nil {
		return err
	}
	err = Crowdsec.RegisterFeature(PapiClient)
	if err != nil {
		return err
	}
	err = Crowdsec.RegisterFeature(Re2Support)
	if err != nil {
		return err
	}

	return nil
}
