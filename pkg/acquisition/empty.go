package acquisition

import (
	"errors"
	"io"

	"gopkg.in/yaml.v3"
)

// IsEmptyYAML reads one YAML document from r and returns true
// if it is empty or contains only comments and no meaningful content.
// To filter out multiple documents, split them first and call this function on each one.
func IsEmptyYAML(r io.Reader) (bool, error) {
	dec := yaml.NewDecoder(r)

	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return true, nil
		}
		return false, err
	}

	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return true, nil
	}

	root := doc.Content[0]
	switch root.Kind { //nolint:exhaustive
	case yaml.MappingNode, yaml.SequenceNode:
		return len(root.Content) == 0, nil
	case yaml.ScalarNode:
		return root.Value == "", nil
	default:
		return true, nil
	}
}
