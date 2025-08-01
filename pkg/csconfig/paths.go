package csconfig

import (
	"fmt"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

func ensureAbsolutePath(p *string) error {
	// TODO: this will become a straight IsAbs check + return error
	var err error

	if *p == "" {
		return nil
	}

	if !filepath.IsAbs(*p) {
		log.Warnf("Using a relative path for %q is deprecated and will be disallowed in a future release", *p)
	}

	*p, err = filepath.Abs(*p)
	if err != nil {
		return fmt.Errorf("failed to get absolute path of %q: %w", *p, err)
	}

	return nil
}
