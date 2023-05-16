package describegroups

import (
	"github.com/segmentio/kafka-go/protocol"
)

func init() {
	protocol.Register(&Request{}, &Response{})
}

// Detailed API definition: https://kafka.apache.org/protocol#The_Messages_DescribeGroups
type Request struct {
	Groups                      []string `kafka:"min=v0,max=v4"`
	IncludeAuthorizedOperations bool     `kafka:"min=v3,max=v4"`
}

func (r *Request) ApiKey() protocol.ApiKey { return protocol.DescribeGroups }

func (r *Request) Group() string {
	return r.Groups[0]
}

func (r *Request) Split(cluster protocol.Cluster) (
	[]protocol.Message,
	protocol.Merger,
	error,
) {
	messages := []protocol.Message{}

	// Split requests by group since they'll need to go to different coordinators.
	for _, group := range r.Groups {
		messages = append(
			messages,
			&Request{
				Groups:                      []string{group},
				IncludeAuthorizedOperations: r.IncludeAuthorizedOperations,
			},
		)
	}

	return messages, new(Response), nil
}

type Response struct {
	ThrottleTimeMs int32           `kafka:"min=v1,max=v4"`
	Groups         []ResponseGroup `kafka:"min=v0,max=v4"`
}

type ResponseGroup struct {
	ErrorCode            int16                 `kafka:"min=v0,max=v4"`
	GroupID              string                `kafka:"min=v0,max=v4"`
	GroupState           string                `kafka:"min=v0,max=v4"`
	ProtocolType         string                `kafka:"min=v0,max=v4"`
	ProtocolData         string                `kafka:"min=v0,max=v4"`
	Members              []ResponseGroupMember `kafka:"min=v0,max=v4"`
	AuthorizedOperations int32                 `kafka:"min=v3,max=v4"`
}

type ResponseGroupMember struct {
	MemberID         string `kafka:"min=v0,max=v4"`
	GroupInstanceID  string `kafka:"min=v4,max=v4,nullable"`
	ClientID         string `kafka:"min=v0,max=v4"`
	ClientHost       string `kafka:"min=v0,max=v4"`
	MemberMetadata   []byte `kafka:"min=v0,max=v4"`
	MemberAssignment []byte `kafka:"min=v0,max=v4"`
}

func (r *Response) ApiKey() protocol.ApiKey { return protocol.DescribeGroups }

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
		response.Groups = append(response.Groups, m.(*Response).Groups...)
	}

	return response, nil
}
