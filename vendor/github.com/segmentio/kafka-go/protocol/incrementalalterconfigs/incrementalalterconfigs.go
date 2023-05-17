package incrementalalterconfigs

import (
	"errors"
	"strconv"

	"github.com/segmentio/kafka-go/protocol"
)

const (
	resourceTypeBroker int8 = 4
)

func init() {
	protocol.Register(&Request{}, &Response{})
}

// Detailed API definition: https://kafka.apache.org/protocol#The_Messages_IncrementalAlterConfigs
type Request struct {
	Resources    []RequestResource `kafka:"min=v0,max=v0"`
	ValidateOnly bool              `kafka:"min=v0,max=v0"`
}

type RequestResource struct {
	ResourceType int8            `kafka:"min=v0,max=v0"`
	ResourceName string          `kafka:"min=v0,max=v0"`
	Configs      []RequestConfig `kafka:"min=v0,max=v0"`
}

type RequestConfig struct {
	Name            string `kafka:"min=v0,max=v0"`
	ConfigOperation int8   `kafka:"min=v0,max=v0"`
	Value           string `kafka:"min=v0,max=v0,nullable"`
}

func (r *Request) ApiKey() protocol.ApiKey { return protocol.IncrementalAlterConfigs }

func (r *Request) Broker(cluster protocol.Cluster) (protocol.Broker, error) {
	// Check that at most only one broker is being updated.
	//
	// TODO: Support updating multiple brokers in a single request.
	brokers := map[string]struct{}{}
	for _, resource := range r.Resources {
		if resource.ResourceType == resourceTypeBroker {
			brokers[resource.ResourceName] = struct{}{}
		}
	}
	if len(brokers) > 1 {
		return protocol.Broker{},
			errors.New("Updating more than one broker in a single request is not supported yet")
	}

	for _, resource := range r.Resources {
		if resource.ResourceType == resourceTypeBroker {
			brokerID, err := strconv.Atoi(resource.ResourceName)
			if err != nil {
				return protocol.Broker{}, err
			}

			return cluster.Brokers[int32(brokerID)], nil
		}
	}

	return cluster.Brokers[cluster.Controller], nil
}

type Response struct {
	ThrottleTimeMs int32                   `kafka:"min=v0,max=v0"`
	Responses      []ResponseAlterResponse `kafka:"min=v0,max=v0"`
}

type ResponseAlterResponse struct {
	ErrorCode    int16  `kafka:"min=v0,max=v0"`
	ErrorMessage string `kafka:"min=v0,max=v0,nullable"`
	ResourceType int8   `kafka:"min=v0,max=v0"`
	ResourceName string `kafka:"min=v0,max=v0"`
}

func (r *Response) ApiKey() protocol.ApiKey { return protocol.IncrementalAlterConfigs }
