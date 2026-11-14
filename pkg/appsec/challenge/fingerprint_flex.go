// fingerprint_flex.go holds the tolerant decoding of object-shaped signals.
// The bundle wraps every collector in a try/catch and substitutes a sentinel
// string — "ERROR", "SKIPPED", "NA" or "INIT" — for whatever the collector was
// supposed to return. FlexBool / FlexInt (fingerprint.go) absorb that for
// scalars; flexStruct does it for the signals that are whole objects.

package challenge

import (
	"encoding/json"
)

// flexStruct decodes an object-shaped signal, tolerating the sentinel string
// the bundle substitutes when the collector threw: dst is left zero and no
// error is reported, so one blown collector no longer rejects the whole
// submission. Anything else decodes normally — malformed payloads still fail.
//
// dst must point at a method-stripped copy of the target type (declare
// `type alias T` in the caller and convert); passing the target type itself
// recurses back into its own UnmarshalJSON.
func flexStruct[T any](data []byte, dst *T) error {
	var sentinel string
	if err := json.Unmarshal(data, &sentinel); err == nil {
		return nil
	}

	return json.Unmarshal(data, dst)
}

func (v *fingerprintScreenResolution) UnmarshalJSON(data []byte) error {
	type alias fingerprintScreenResolution

	return flexStruct(data, (*alias)(v))
}

func (v *fingerprintMultimediaDevices) UnmarshalJSON(data []byte) error {
	type alias fingerprintMultimediaDevices

	return flexStruct(data, (*alias)(v))
}

func (v *fingerprintDeviceMediaQueries) UnmarshalJSON(data []byte) error {
	type alias fingerprintDeviceMediaQueries

	return flexStruct(data, (*alias)(v))
}

func (v *fingerprintDeviceKeyboard) UnmarshalJSON(data []byte) error {
	type alias fingerprintDeviceKeyboard

	return flexStruct(data, (*alias)(v))
}

func (v *fingerprintBrowserFeatures) UnmarshalJSON(data []byte) error {
	type alias fingerprintBrowserFeatures

	return flexStruct(data, (*alias)(v))
}

func (v *fingerprintBrowserPlugins) UnmarshalJSON(data []byte) error {
	type alias fingerprintBrowserPlugins

	return flexStruct(data, (*alias)(v))
}

func (v *fingerprintBrowserExtensions) UnmarshalJSON(data []byte) error {
	type alias fingerprintBrowserExtensions

	return flexStruct(data, (*alias)(v))
}

func (v *fingerprintBrowserHighEntropyValues) UnmarshalJSON(data []byte) error {
	type alias fingerprintBrowserHighEntropyValues

	return flexStruct(data, (*alias)(v))
}

func (v *fingerprintBrowserToSourceError) UnmarshalJSON(data []byte) error {
	type alias fingerprintBrowserToSourceError

	return flexStruct(data, (*alias)(v))
}

func (v *fingerprintBrowserAI) UnmarshalJSON(data []byte) error {
	type alias fingerprintBrowserAI

	return flexStruct(data, (*alias)(v))
}

func (v *fingerprintGraphicsWebGL) UnmarshalJSON(data []byte) error {
	type alias fingerprintGraphicsWebGL

	return flexStruct(data, (*alias)(v))
}

func (v *fingerprintGraphicsWebGPU) UnmarshalJSON(data []byte) error {
	type alias fingerprintGraphicsWebGPU

	return flexStruct(data, (*alias)(v))
}

func (v *fingerprintGraphicsCanvas) UnmarshalJSON(data []byte) error {
	type alias fingerprintGraphicsCanvas

	return flexStruct(data, (*alias)(v))
}

func (c *fingerprintCodecs) UnmarshalJSON(data []byte) error {
	type alias fingerprintCodecs

	return flexStruct(data, (*alias)(c))
}

func (v *fingerprintLocaleInternationalization) UnmarshalJSON(data []byte) error {
	type alias fingerprintLocaleInternationalization

	return flexStruct(data, (*alias)(v))
}

func (v *fingerprintLocaleLanguages) UnmarshalJSON(data []byte) error {
	type alias fingerprintLocaleLanguages

	return flexStruct(data, (*alias)(v))
}

func (v *fingerprintIframeContext) UnmarshalJSON(data []byte) error {
	type alias fingerprintIframeContext

	return flexStruct(data, (*alias)(v))
}

func (v *fingerprintWebWorkerContext) UnmarshalJSON(data []byte) error {
	type alias fingerprintWebWorkerContext

	return flexStruct(data, (*alias)(v))
}
