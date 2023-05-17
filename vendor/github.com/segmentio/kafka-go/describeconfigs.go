package kafka

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/segmentio/kafka-go/protocol/describeconfigs"
)

// DescribeConfigsRequest represents a request sent to a kafka broker to describe configs.
type DescribeConfigsRequest struct {
	// Address of the kafka broker to send the request to.
	Addr net.Addr

	// List of resources to update.
	Resources []DescribeConfigRequestResource

	// Ignored if API version is less than v1
	IncludeSynonyms bool

	// Ignored if API version is less than v3
	IncludeDocumentation bool
}

type DescribeConfigRequestResource struct {
	// Resource Type
	ResourceType ResourceType

	// Resource Name
	ResourceName string

	// ConfigNames is a list of configurations to update.
	ConfigNames []string
}

// DescribeConfigsResponse represents a response from a kafka broker to a describe config request.
type DescribeConfigsResponse struct {
	// The amount of time that the broker throttled the request.
	Throttle time.Duration

	// Resources
	Resources []DescribeConfigResponseResource
}

// DescribeConfigResponseResource.
type DescribeConfigResponseResource struct {
	// Resource Type
	ResourceType int8

	// Resource Name
	ResourceName string

	// Error
	Error error

	// ConfigEntries
	ConfigEntries []DescribeConfigResponseConfigEntry
}

// DescribeConfigResponseConfigEntry.
type DescribeConfigResponseConfigEntry struct {
	ConfigName  string
	ConfigValue string
	ReadOnly    bool

	// Ignored if API version is greater than v0
	IsDefault bool

	// Ignored if API version is less than v1
	ConfigSource int8

	IsSensitive bool

	// Ignored if API version is less than v1
	ConfigSynonyms []DescribeConfigResponseConfigSynonym

	// Ignored if API version is less than v3
	ConfigType int8

	// Ignored if API version is less than v3
	ConfigDocumentation string
}

// DescribeConfigResponseConfigSynonym.
type DescribeConfigResponseConfigSynonym struct {
	// Ignored if API version is less than v1
	ConfigName string

	// Ignored if API version is less than v1
	ConfigValue string

	// Ignored if API version is less than v1
	ConfigSource int8
}

// DescribeConfigs sends a config altering request to a kafka broker and returns the
// response.
func (c *Client) DescribeConfigs(ctx context.Context, req *DescribeConfigsRequest) (*DescribeConfigsResponse, error) {
	resources := make([]describeconfigs.RequestResource, len(req.Resources))

	for i, t := range req.Resources {
		resources[i] = describeconfigs.RequestResource{
			ResourceType: int8(t.ResourceType),
			ResourceName: t.ResourceName,
			ConfigNames:  t.ConfigNames,
		}
	}

	m, err := c.roundTrip(ctx, req.Addr, &describeconfigs.Request{
		Resources:            resources,
		IncludeSynonyms:      req.IncludeSynonyms,
		IncludeDocumentation: req.IncludeDocumentation,
	})
	if err != nil {
		return nil, fmt.Errorf("kafka.(*Client).DescribeConfigs: %w", err)
	}

	res := m.(*describeconfigs.Response)
	ret := &DescribeConfigsResponse{
		Throttle:  makeDuration(res.ThrottleTimeMs),
		Resources: make([]DescribeConfigResponseResource, len(res.Resources)),
	}

	for i, t := range res.Resources {

		configEntries := make([]DescribeConfigResponseConfigEntry, len(t.ConfigEntries))
		for j, v := range t.ConfigEntries {

			configSynonyms := make([]DescribeConfigResponseConfigSynonym, len(v.ConfigSynonyms))
			for k, cs := range v.ConfigSynonyms {
				configSynonyms[k] = DescribeConfigResponseConfigSynonym{
					ConfigName:   cs.ConfigName,
					ConfigValue:  cs.ConfigValue,
					ConfigSource: cs.ConfigSource,
				}
			}

			configEntries[j] = DescribeConfigResponseConfigEntry{
				ConfigName:          v.ConfigName,
				ConfigValue:         v.ConfigValue,
				ReadOnly:            v.ReadOnly,
				ConfigSource:        v.ConfigSource,
				IsDefault:           v.IsDefault,
				IsSensitive:         v.IsSensitive,
				ConfigSynonyms:      configSynonyms,
				ConfigType:          v.ConfigType,
				ConfigDocumentation: v.ConfigDocumentation,
			}
		}

		ret.Resources[i] = DescribeConfigResponseResource{
			ResourceType:  t.ResourceType,
			ResourceName:  t.ResourceName,
			Error:         makeError(t.ErrorCode, t.ErrorMessage),
			ConfigEntries: configEntries,
		}
	}

	return ret, nil
}
