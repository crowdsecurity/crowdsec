package types

import (
	"net"

	"github.com/jinzhu/gorm"
)

//Source is the generic representation of a source ip implicated in events / overflows. It contains both information extracted directly from logs and enrichment
type Source struct {
	gorm.Model                   `json:"-"`
	Ip                           net.IP
	Range                        net.IPNet
	AutonomousSystemNumber       string
	AutonomousSystemOrganization string
	Country                      string
	Latitude                     float64
	Longitude                    float64
	Flags                        map[string]bool //a list of flags we can set
}
