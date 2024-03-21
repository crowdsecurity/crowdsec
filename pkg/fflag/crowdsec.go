package fflag

var Crowdsec = FeatureRegister{EnvPrefix: "CROWDSEC_FEATURE_"}

var CscliSetup = &Feature{Name: "cscli_setup", Description: "Enable cscli setup command (service detection)"}
var DisableHttpRetryBackoff = &Feature{Name: "disable_http_retry_backoff", Description: "Disable http retry backoff"}
var ChunkedDecisionsStream = &Feature{Name: "chunked_decisions_stream", Description: "Enable chunked decisions stream"}
var PapiClient = &Feature{Name: "papi_client", Description: "Enable Polling API client", State: DeprecatedState}
var Re2GrokSupport = &Feature{Name: "re2_grok_support", Description: "Enable RE2 support for GROK patterns"}
var Re2RegexpInfileSupport = &Feature{Name: "re2_regexp_in_file_support", Description: "Enable RE2 support for RegexpInFile expr helper"}
var CAPIUsageMetrics = &Feature{Name: "capi_usage_metrics", Description: "Enable usage metrics push to CAPI"}

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

	err = Crowdsec.RegisterFeature(CAPIUsageMetrics)
	if err != nil {
		return err
	}

	return nil
}
