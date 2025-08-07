package setup

import (
	"bytes"
	"slices"

	goccyyaml "github.com/goccy/go-yaml"
	"gopkg.in/yaml.v3"
)

func (s *Setup) CollectHubSpecs() []HubSpec {
	ret := []HubSpec{}

	for _, svc := range s.Plans {
		ret = append(ret, svc.HubSpec)
	}

	return ret
}

func (s *Setup) CollectAcquisitionSpecs() []AcquisitionSpec {
	ret := make([]AcquisitionSpec, len(s.Plans))

	for idx, svc := range s.Plans {
		// XXX: assume no filename conflict
		ret[idx] = svc.AcquisitionSpec
	}

	return ret
}

func (s *Setup) DetectedServices() []string {
	ret := make([]string, 0, len(s.Plans))

	for _, svc := range s.Plans {
		ret = append(ret, svc.Name)
	}

	slices.Sort(ret)

	return ret
}

func (s *Setup) ToYAML(outYaml bool) ([]byte, error) {
	var (
		ret []byte
		err error
	)

	buf := &bytes.Buffer{}
	enc := yaml.NewEncoder(buf)
	enc.SetIndent(2)

	if err = enc.Encode(s); err != nil {
		return nil, err
	}

	if err = enc.Close(); err != nil {
		return nil, err
	}

	ret = buf.Bytes()

	if !outYaml {
		// take a general approach to output json, so we avoid the
		// double tags in the structures and can use go-yaml features
		// missing from the json package
		ret, err = goccyyaml.YAMLToJSON(ret)
		if err != nil {
			return nil, err
		}
	}

	return ret, nil
}
