//go:build !linux

package csplugin

import (
	"os"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
)

func getUUID() (string, error) {
	u, err := uuid.NewV4()
	if err != nil {
		return "", errors.Wrap(err, "failed to generate UUID")
	}
	return u, nil
}
