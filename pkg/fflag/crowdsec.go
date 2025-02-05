package fflag

var Crowdsec = FeatureRegister{EnvPrefix: "CROWDSEC_FEATURE_"}

var (
	CscliSetup              = &Feature{Name: "cscli_setup", Description: "Enable cscli setup command (service detection)"}
	DisableHttpRetryBackoff = &Feature{Name: "disable_http_retry_backoff", Description: "Disable http retry backoff"}
	ChunkedDecisionsStream  = &Feature{Name: "chunked_decisions_stream", Description: "Enable chunked decisions stream"}
	PapiClient              = &Feature{Name: "papi_client", Description: "Enable Polling API client", State: DeprecatedState}
	Re2GrokSupport          = &Feature{Name: "re2_grok_support", Description: "Enable RE2 support for GROK patterns"}
	Re2RegexpInfileSupport  = &Feature{Name: "re2_regexp_in_file_support", Description: "Enable RE2 support for RegexpInFile expr helper"}
)

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

	err = Crowdsec.RegisterFeature(Re2GrokSupport)
	if err != nil {
		return err
	}

	err = Crowdsec.RegisterFeature(Re2RegexpInfileSupport)
	if err != nil {
		return err
	}

	return nil
}
