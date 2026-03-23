package fflag

import "runtime"

var Crowdsec = FeatureRegister{EnvPrefix: "CROWDSEC_FEATURE_"}

var (
	DisableHttpRetryBackoff = &Feature{Name: "disable_http_retry_backoff", Description: "Disable http retry backoff"}
	ChunkedDecisionsStream  = &Feature{Name: "chunked_decisions_stream", Description: "Enable chunked decisions stream"}
	PapiClient              = &Feature{Name: "papi_client", Description: "Enable Polling API client", State: DeprecatedState}
	// The state will be set to deprecated for linux only.
	Re2GrokSupport = &Feature{Name: "re2_grok_support", Description: "Enable RE2 support for GROK patterns"}
	// This one is only available on OS where RE2 support is enabled by default (linux only at the moment)
	Re2DisableGrokSupport  = &Feature{Name: "re2_disable_grok_support", Description: "Disable RE2 support for GROK patterns (linux only)"}
	Re2RegexpInfileSupport = &Feature{Name: "re2_regexp_in_file_support", Description: "Enable RE2 support for RegexpInFile expr helper"}
	PProfBlockProfile      = &Feature{Name: "pprof_block_profile", Description: "Enable pprof block/mutex profiling. Do not use unless instructed by CrowdSec support"}
)

//revive:disable:if-return
func RegisterAllFeatures() error {
	if err := Crowdsec.RegisterFeature(DisableHttpRetryBackoff); err != nil {
		return err
	}

	if err := Crowdsec.RegisterFeature(ChunkedDecisionsStream); err != nil {
		return err
	}

	if err := Crowdsec.RegisterFeature(PapiClient); err != nil {
		return err
	}

	if err := Crowdsec.RegisterFeature(Re2RegexpInfileSupport); err != nil {
		return err
	}

	if err := Crowdsec.RegisterFeature(PProfBlockProfile); err != nil {
		return err
	}

	if runtime.GOOS == "linux" {
		// This cannot actually fail in a release, so the state will always be set
		if err := Crowdsec.RegisterFeature(Re2DisableGrokSupport); err != nil {
			return err
		}
		Re2GrokSupport.State = DeprecatedState
	}

	if err := Crowdsec.RegisterFeature(Re2GrokSupport); err != nil {
		return err
	}

	return nil
}

//revice:enable:if-return
