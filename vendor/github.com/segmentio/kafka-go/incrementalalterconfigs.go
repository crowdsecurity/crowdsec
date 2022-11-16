package kafka

import (
	"context"
	"net"

	"github.com/segmentio/kafka-go/protocol/incrementalalterconfigs"
)

type ConfigOperation int8

const (
	ConfigOperationSet      ConfigOperation = 0
	ConfigOperationDelete   ConfigOperation = 1
	ConfigOperationAppend   ConfigOperation = 2
	ConfigOperationSubtract ConfigOperation = 3
)

// IncrementalAlterConfigsRequest is a request to the IncrementalAlterConfigs API.
type IncrementalAlterConfigsRequest struct {
	// Addr is the address of the kafka broker to send the request to.
	Addr net.Addr

	// Resources contains the list of resources to update configs for.
	Resources []IncrementalAlterConfigsRequestResource

	// ValidateOnly indicates whether Kafka should validate the changes without actually
	// applying them.
	ValidateOnly bool
}

// IncrementalAlterConfigsRequestResource contains the details of a single resource type whose
// configs should be altered.
type IncrementalAlterConfigsRequestResource struct {
	// ResourceType is the type of resource to update.
	ResourceType ResourceType

	// ResourceName is the name of the resource to update (i.e., topic name or broker ID).
	ResourceName string

	// Configs contains the list of config key/values to update.
	Configs []IncrementalAlterConfigsRequestConfig
}

// IncrementalAlterConfigsRequestConfig describes a single config key/value pair that should
// be altered.
type IncrementalAlterConfigsRequestConfig struct {
	// Name is the name of the config.
	Name string

	// Value is the value to set for this config.
	Value string

	// ConfigOperation indicates how this config should be updated (e.g., add, delete, etc.).
	ConfigOperation ConfigOperation
}

// IncrementalAlterConfigsResponse is a response from the IncrementalAlterConfigs API.
type IncrementalAlterConfigsResponse struct {
	// Resources contains details of each resource config that was updated.
	Resources []IncrementalAlterConfigsResponseResource
}

// IncrementalAlterConfigsResponseResource contains the response details for a single resource
// whose configs were updated.
type IncrementalAlterConfigsResponseResource struct {
	// Error is set to a non-nil value if an error occurred while updating this specific
	// config.
	Error error

	// ResourceType is the type of resource that was updated.
	ResourceType ResourceType

	// ResourceName is the name of the resource that was updated.
	ResourceName string
}

func (c *Client) IncrementalAlterConfigs(
	ctx context.Context,
	req *IncrementalAlterConfigsRequest,
) (*IncrementalAlterConfigsResponse, error) {
	apiReq := &incrementalalterconfigs.Request{
		ValidateOnly: req.ValidateOnly,
	}

	for _, res := range req.Resources {
		apiRes := incrementalalterconfigs.RequestResource{
			ResourceType: int8(res.ResourceType),
			ResourceName: res.ResourceName,
		}

		for _, config := range res.Configs {
			apiRes.Configs = append(
				apiRes.Configs,
				incrementalalterconfigs.RequestConfig{
					Name:            config.Name,
					Value:           config.Value,
					ConfigOperation: int8(config.ConfigOperation),
				},
			)
		}

		apiReq.Resources = append(
			apiReq.Resources,
			apiRes,
		)
	}

	protoResp, err := c.roundTrip(
		ctx,
		req.Addr,
		apiReq,
	)
	if err != nil {
		return nil, err
	}

	resp := &IncrementalAlterConfigsResponse{}

	apiResp := protoResp.(*incrementalalterconfigs.Response)
	for _, res := range apiResp.Responses {
		resp.Resources = append(
			resp.Resources,
			IncrementalAlterConfigsResponseResource{
				Error:        makeError(res.ErrorCode, res.ErrorMessage),
				ResourceType: ResourceType(res.ResourceType),
				ResourceName: res.ResourceName,
			},
		)
	}

	return resp, nil
}
