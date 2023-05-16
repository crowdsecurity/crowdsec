package kafka

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/segmentio/kafka-go/protocol/alterconfigs"
)

// AlterConfigsRequest represents a request sent to a kafka broker to alter configs.
type AlterConfigsRequest struct {
	// Address of the kafka broker to send the request to.
	Addr net.Addr

	// List of resources to update.
	Resources []AlterConfigRequestResource

	// When set to true, topics are not created but the configuration is
	// validated as if they were.
	ValidateOnly bool
}

type AlterConfigRequestResource struct {
	// Resource Type
	ResourceType ResourceType

	// Resource Name
	ResourceName string

	// Configs is a list of configuration updates.
	Configs []AlterConfigRequestConfig
}

type AlterConfigRequestConfig struct {
	// Configuration key name
	Name string

	// The value to set for the configuration key.
	Value string
}

// AlterConfigsResponse represents a response from a kafka broker to an alter config request.
type AlterConfigsResponse struct {
	// Duration for which the request was throttled due to a quota violation.
	Throttle time.Duration

	// Mapping of topic names to errors that occurred while attempting to create
	// the topics.
	//
	// The errors contain the kafka error code. Programs may use the standard
	// errors.Is function to test the error against kafka error codes.
	Errors map[AlterConfigsResponseResource]error
}

// AlterConfigsResponseResource helps map errors to specific resources in an
// alter config response.
type AlterConfigsResponseResource struct {
	Type int8
	Name string
}

// AlterConfigs sends a config altering request to a kafka broker and returns the
// response.
func (c *Client) AlterConfigs(ctx context.Context, req *AlterConfigsRequest) (*AlterConfigsResponse, error) {
	resources := make([]alterconfigs.RequestResources, len(req.Resources))

	for i, t := range req.Resources {
		configs := make([]alterconfigs.RequestConfig, len(t.Configs))
		for j, v := range t.Configs {
			configs[j] = alterconfigs.RequestConfig{
				Name:  v.Name,
				Value: v.Value,
			}
		}
		resources[i] = alterconfigs.RequestResources{
			ResourceType: int8(t.ResourceType),
			ResourceName: t.ResourceName,
			Configs:      configs,
		}
	}

	m, err := c.roundTrip(ctx, req.Addr, &alterconfigs.Request{
		Resources:    resources,
		ValidateOnly: req.ValidateOnly,
	})

	if err != nil {
		return nil, fmt.Errorf("kafka.(*Client).AlterConfigs: %w", err)
	}

	res := m.(*alterconfigs.Response)
	ret := &AlterConfigsResponse{
		Throttle: makeDuration(res.ThrottleTimeMs),
		Errors:   make(map[AlterConfigsResponseResource]error, len(res.Responses)),
	}

	for _, t := range res.Responses {
		ret.Errors[AlterConfigsResponseResource{
			Type: t.ResourceType,
			Name: t.ResourceName,
		}] = makeError(t.ErrorCode, t.ErrorMessage)
	}

	return ret, nil
}
