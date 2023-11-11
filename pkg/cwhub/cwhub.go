// Package cwhub is responsible for installing and upgrading the local hub files.
//
// This includes retrieving the index, the items to install (parsers, scenarios, data files...)
// and managing the dependencies and taints.
package cwhub

import (
	"net/http"
	"time"
)

var hubClient = &http.Client{
	Timeout: 20 * time.Second,
}
