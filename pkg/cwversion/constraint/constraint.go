package constraint

import (
	"fmt"

	goversion "github.com/hashicorp/go-version"
)

const (
	Parser   = ">= 1.0, <= 3.0"
	Scenario = ">= 1.0, <= 3.0"
	API      = "v1"
	Acquis   = ">= 1.0, < 2.0"
)

func Satisfies(strvers string, constraint string) (bool, error) {
	vers, err := goversion.NewVersion(strvers)
	if err != nil {
		return false, fmt.Errorf("failed to parse '%s': %w", strvers, err)
	}

	constraints, err := goversion.NewConstraint(constraint)
	if err != nil {
		return false, fmt.Errorf("failed to parse constraint '%s'", constraint)
	}

	if !constraints.Check(vers) {
		return false, nil
	}

	return true, nil
}
