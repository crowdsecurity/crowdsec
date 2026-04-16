package acquisition

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/goccy/go-yaml"
)

// format a compact error without schema location for testing purposes.
func compactSchemaErr(err error) error {
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return err
	}

	out := ve.BasicOutput()
	if out == nil || len(out.Errors) == 0 {
		// Fallback; this may include schema URL, but it's better than losing the error.
		return err
	}

	msgs := make([]string, 0, len(out.Errors))
	for _, u := range out.Errors {
		if u.Error == nil {
			continue
		}
		loc := u.InstanceLocation
		if loc == "" {
			loc = "/"
		}
		msgs = append(msgs, fmt.Sprintf("%s: %s", loc, u.Error.String()))
	}

	sort.Strings(msgs)
	return fmt.Errorf("%s", strings.Join(msgs, "; "))
}

// ValidateYAML validates configYAML against schemaPath.
func ValidateYAML(configYAML []byte, schemaPath string) error {
	if schemaPath == "" {
		return errors.New("no schema provided")
	}

	configJSON, err := yaml.YAMLToJSON(configYAML)
	if err != nil {
		return fmt.Errorf("config: YAML->JSON: %w", err)
	}

	configDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(configJSON))
	if err != nil {
		return fmt.Errorf("config: decode JSON: %w", err)
	}

	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)

	schemaYAML, err := os.ReadFile(schemaPath)
	if err != nil {
		return fmt.Errorf("read schema %q: %w", schemaPath, err)
	}

	schemaJSON, err := yaml.YAMLToJSON(schemaYAML)
	if err != nil {
		return fmt.Errorf("schema %q: YAML->JSON: %w", schemaPath, err)
	}

	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
	if err != nil {
		return fmt.Errorf("schema %q: decode JSON: %w", schemaPath, err)
	}

	abs, err := filepath.Abs(schemaPath)
	if err != nil {
		return fmt.Errorf("abs %q: %w", schemaPath, err)
	}

	if err := c.AddResource(abs, schemaDoc); err != nil {
		return fmt.Errorf("add schema resource %q: %w", abs, err)
	}

	sch, err := c.Compile(abs)
	if err != nil {
		return fmt.Errorf("compile schema %q: %w", abs, err)
	}

	if err := sch.Validate(configDoc); err != nil {
		var ve *jsonschema.ValidationError
		if errors.As(err, &ve) {
			return compactSchemaErr(ve)
		}
		return err
	}

	return nil
}
