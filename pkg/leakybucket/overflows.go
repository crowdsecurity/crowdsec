package leakybucket

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func FormatOverflow(l *Leaky, queue *Queue) types.SignalOccurence {
	var am string

	l.logger.Debugf("Overflow (start: %s, end: %s)", l.First_ts, l.Ovflw_ts)

	sig := types.SignalOccurence{
		Scenario:      l.Name,
		Bucket_id:     l.Uuid,
		Alert_message: am,
		Start_at:      l.First_ts,
		Stop_at:       l.Ovflw_ts,
		Events_count:  l.Total_count,
		Capacity:      l.Capacity,
		Reprocess:     l.Reprocess,
		Leak_speed:    l.Leakspeed,
		MapKey:        l.Mapkey,
		Sources:       make(map[string]types.Source),
		Labels:        l.BucketConfig.Labels,
	}

	for _, evt := range queue.Queue {
		//either it's a collection of logs, or a collection of past overflows being reprocessed.
		//one overflow can have multiple sources for example
		if evt.Type == types.LOG {
			if _, ok := evt.Meta["source_ip"]; !ok {
				continue
			}
			source_ip := evt.Meta["source_ip"]
			if _, ok := sig.Sources[source_ip]; !ok {
				src := types.Source{}
				src.Ip = net.ParseIP(source_ip)
				if v, ok := evt.Enriched["ASNNumber"]; ok {
					src.AutonomousSystemNumber = v
				}
				if v, ok := evt.Enriched["IsoCode"]; ok {
					src.Country = v
				}
				if v, ok := evt.Enriched["ASNOrg"]; ok {
					src.AutonomousSystemOrganization = v
				}
				if v, ok := evt.Enriched["Latitude"]; ok {
					src.Latitude, _ = strconv.ParseFloat(v, 32)
				}
				if v, ok := evt.Enriched["Longitude"]; ok {
					src.Longitude, _ = strconv.ParseFloat(v, 32)
				}
				if v, ok := evt.Meta["SourceRange"]; ok {
					_, ipNet, err := net.ParseCIDR(v)
					if err != nil {
						l.logger.Errorf("Declared range %s of %s can't be parsed", v, src.Ip.String())
					} else if ipNet != nil {
						src.Range = *ipNet
						l.logger.Tracef("Valid range from %s : %s", src.Ip.String(), src.Range.String())
					}
				}
				sig.Sources[source_ip] = src
				if sig.Source == nil {
					sig.Source = &src
					sig.Source_ip = src.Ip.String()
					sig.Source_AutonomousSystemNumber = src.AutonomousSystemNumber
					sig.Source_AutonomousSystemOrganization = src.AutonomousSystemOrganization
					sig.Source_Country = src.Country
					sig.Source_range = src.Range.String()
					sig.Source_Latitude = src.Latitude
					sig.Source_Longitude = src.Longitude
				}
			}
		} else if evt.Type == types.OVFLW {
			for _, src := range evt.Overflow.Sources {
				if _, ok := sig.Sources[src.Ip.String()]; !ok {
					sig.Sources[src.Ip.String()] = src
					if sig.Source == nil {
						l.logger.Tracef("populating overflow with source : %+v", src)
						src := src //src will be reused, copy before giving pointer
						sig.Source = &src
						sig.Source_ip = src.Ip.String()
						sig.Source_AutonomousSystemNumber = src.AutonomousSystemNumber
						sig.Source_AutonomousSystemOrganization = src.AutonomousSystemOrganization
						sig.Source_Country = src.Country
						sig.Source_range = src.Range.String()
						sig.Source_Latitude = src.Latitude
						sig.Source_Longitude = src.Longitude
					}
				}

			}

		}

		strret, err := json.Marshal(evt.Meta)
		if err != nil {
			l.logger.Errorf("failed to marshal ret : %v", err)
			continue
		}
		if sig.Source != nil {
			sig.Events_sequence = append(sig.Events_sequence, types.EventSequence{
				Source:                              *sig.Source,
				Source_ip:                           sig.Source_ip,
				Source_AutonomousSystemNumber:       sig.Source.AutonomousSystemNumber,
				Source_AutonomousSystemOrganization: sig.Source.AutonomousSystemOrganization,
				Source_Country:                      sig.Source.Country,
				Serialized:                          string(strret),
				Time:                                l.First_ts})
		} else {
			l.logger.Warningf("Event without source ?!")
		}
	}

	if len(sig.Sources) > 1 {
		am = fmt.Sprintf("%d IPs", len(sig.Sources))
	} else if len(sig.Sources) == 1 {
		if sig.Source != nil {
			am = sig.Source.Ip.String()
		} else {
			am = "??"
		}
	} else {
		am = "UNKNOWN"
	}

	am += fmt.Sprintf(" performed '%s' (%d events over %s) at %s", l.Name, l.Total_count, l.Ovflw_ts.Sub(l.First_ts), l.Ovflw_ts)
	sig.Alert_message = am
	return sig
}
