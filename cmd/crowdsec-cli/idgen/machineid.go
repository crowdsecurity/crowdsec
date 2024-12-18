package idgen

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/machineid"
)

// Returns a unique identifier for each crowdsec installation, using an
// identifier of the OS installation where available, otherwise a random
// string.
func generateMachineIDPrefix() (string, error) {
	prefix, err := machineid.ID()
	if err == nil {
		return prefix, nil
	}

	log.Debugf("failed to get machine-id with usual files: %s", err)

	bID, err := uuid.NewRandom()
	if err == nil {
		return bID.String(), nil
	}

	return "", fmt.Errorf("generating machine id: %w", err)
}

// Generate a unique identifier, composed by a prefix and a random suffix.
// The prefix can be provided by a parameter to use in test environments.
func GenerateMachineID(prefix string) (string, error) {
	var err error
	if prefix == "" {
		prefix, err = generateMachineIDPrefix()
	}

	if err != nil {
		return "", err
	}

	prefix = strings.ReplaceAll(prefix, "-", "")[:32]

	suffix, err := GeneratePassword(16)
	if err != nil {
		return "", err
	}

	return prefix + suffix, nil
}
