package fflag

var Crowdsec = FeatureRegister{EnvPrefix: "CROWDSEC_FEATURE_"}

var (
	DisableHttpRetryBackoff = &Feature{Name: "disable_http_retry_backoff", Description: "Disable http retry backoff"}
	ChunkedDecisionsStream  = &Feature{Name: "chunked_decisions_stream", Description: "Enable chunked decisions stream"}
	PapiClient              = &Feature{Name: "papi_client", Description: "Enable Polling API client", State: DeprecatedState}
	Re2GrokSupport          = &Feature{Name: "re2_grok_support", Description: "Enable RE2 support for GROK patterns"}
	Re2RegexpInfileSupport  = &Feature{Name: "re2_regexp_in_file_support", Description: "Enable RE2 support for RegexpInFile expr helper"}
	ParsersAutoscale        = &Feature{Name: "parsers_autoscale", Description: "Enable adaptive scaling for parser workers"}
	BucketsAutoscale        = &Feature{Name: "buckets_autoscale", Description: "Enable adaptive scaling for bucket workers"}
	OutputsAutoscale        = &Feature{Name: "outputs_autoscale", Description: "Enable adaptive scaling for output workers"}
)

func RegisterAllFeatures() error {
	err := Crowdsec.RegisterFeature(DisableHttpRetryBackoff)
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

	err = Crowdsec.RegisterFeature(ParsersAutoscale)
	if err != nil {
		return err
	}

	err = Crowdsec.RegisterFeature(BucketsAutoscale)
	if err != nil {
		return err
	}

	err = Crowdsec.RegisterFeature(OutputsAutoscale)
	if err != nil {
		return err
	}

	return nil
}
