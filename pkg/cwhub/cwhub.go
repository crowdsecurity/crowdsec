// Package cwhub is responsible for installing and upgrading the local hub files.
//
// This includes retrieving the index, the items to install (parsers, scenarios, data files...)
// and managing the dependencies and taints.
package cwhub

import (
	"errors"
)

var (
	ErrMissingReference = errors.New("Reference(s) missing in collection")

	RawFileURLTemplate = "https://hub-cdn.crowdsec.net/%s/%s"
	HubBranch          = "master"
)
