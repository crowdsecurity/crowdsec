package setup

import (
	"github.com/Masterminds/semver/v3"
)

type ExprVersion struct{}

// Check returns true if the given version matches the given constraint.
func (ExprVersion) Check(version, constraint string) (bool, error) {
	v, err := semver.NewVersion(version)
	if err != nil {
		return false, err
	}

	c, err := semver.NewConstraint(constraint)
	if err != nil {
		return false, err
	}

	return c.Check(v), nil
}
