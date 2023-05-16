package describeconfigs

import (
	"strconv"

	"github.com/segmentio/kafka-go/protocol"
)

const (
	resourceTypeBroker int8 = 4
)

func init() {
	protocol.Register(&Request{}, &Response{})
}

// Detailed API definition: https://kafka.apache.org/protocol#The_Messages_DescribeConfigs
type Request struct {
	Resources            []RequestResource `kafka:"min=v0,max=v3"`
	IncludeSynonyms      bool              `kafka:"min=v1,max=v3"`
	IncludeDocumentation bool              `kafka:"min=v3,max=v3"`
}

func (r *Request) ApiKey() protocol.ApiKey { return protocol.DescribeConfigs }

func (r *Request) Broker(cluster protocol.Cluster) (protocol.Broker, error) {
	// Broker metadata requests must be sent to the associated broker
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

func (r *Request) Split(cluster protocol.Cluster) (
	[]protocol.Message,
	protocol.Merger,
	error,
) {
	messages := []protocol.Message{}
	topicsMessage := Request{}

	for _, resource := range r.Resources {
		// Split out broker requests to separate brokers
		if resource.ResourceType == resourceTypeBroker {
			messages = append(messages, &Request{
				Resources: []RequestResource{resource},
			})
		} else {
			topicsMessage.Resources = append(
				topicsMessage.Resources, resource,
			)
		}
	}

	if len(topicsMessage.Resources) > 0 {
		messages = append(messages, &topicsMessage)
	}

	return messages, new(Response), nil
}

type RequestResource struct {
	ResourceType int8     `kafka:"min=v0,max=v3"`
	ResourceName string   `kafka:"min=v0,max=v3"`
	ConfigNames  []string `kafka:"min=v0,max=v3,nullable"`
}

type Response struct {
	ThrottleTimeMs int32              `kafka:"min=v0,max=v3"`
	Resources      []ResponseResource `kafka:"min=v0,max=v3"`
}

func (r *Response) ApiKey() protocol.ApiKey { return protocol.DescribeConfigs }

func (r *Response) Merge(requests []protocol.Message, results []interface{}) (
	protocol.Message,
	error,
) {
	response := &Response{}

	for _, result := range results {
		m, err := protocol.Result(result)
		if err != nil {
			return nil, err
		}
		response.Resources = append(
			response.Resources,
			m.(*Response).Resources...,
		)
	}

	return response, nil
}

type ResponseResource struct {
	ErrorCode     int16                 `kafka:"min=v0,max=v3"`
	ErrorMessage  string                `kafka:"min=v0,max=v3,nullable"`
	ResourceType  int8                  `kafka:"min=v0,max=v3"`
	ResourceName  string                `kafka:"min=v0,max=v3"`
	ConfigEntries []ResponseConfigEntry `kafka:"min=v0,max=v3"`
}

type ResponseConfigEntry struct {
	ConfigName          string                  `kafka:"min=v0,max=v3"`
	ConfigValue         string                  `kafka:"min=v0,max=v3,nullable"`
	ReadOnly            bool                    `kafka:"min=v0,max=v3"`
	IsDefault           bool                    `kafka:"min=v0,max=v0"`
	ConfigSource        int8                    `kafka:"min=v1,max=v3"`
	IsSensitive         bool                    `kafka:"min=v0,max=v3"`
	ConfigSynonyms      []ResponseConfigSynonym `kafka:"min=v1,max=v3"`
	ConfigType          int8                    `kafka:"min=v3,max=v3"`
	ConfigDocumentation string                  `kafka:"min=v3,max=v3,nullable"`
}

type ResponseConfigSynonym struct {
	ConfigName   string `kafka:"min=v1,max=v3"`
	ConfigValue  string `kafka:"min=v1,max=v3,nullable"`
	ConfigSource int8   `kafka:"min=v1,max=v3"`
}

var _ protocol.BrokerMessage = (*Request)(nil)
