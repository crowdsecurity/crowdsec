package fflag

var CrowdsecFeatures FeatureMap

func InitCrowdsecFeatures() error {
	var err error
	CrowdsecFeatures, err = NewFeatureMap(map[string]FeatureFlag{"cscli_setup": {}})
	return err
}
