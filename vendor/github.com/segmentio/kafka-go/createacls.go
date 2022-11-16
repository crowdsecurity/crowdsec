package kafka

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/segmentio/kafka-go/protocol/createacls"
)

// CreateACLsRequest represents a request sent to a kafka broker to add
// new ACLs.
type CreateACLsRequest struct {
	// Address of the kafka broker to send the request to.
	Addr net.Addr

	// List of ACL to create.
	ACLs []ACLEntry
}

// CreateACLsResponse represents a response from a kafka broker to an ACL
// creation request.
type CreateACLsResponse struct {
	// The amount of time that the broker throttled the request.
	Throttle time.Duration

	// List of errors that occurred while attempting to create
	// the ACLs.
	//
	// The errors contain the kafka error code. Programs may use the standard
	// errors.Is function to test the error against kafka error codes.
	Errors []error
}

type ACLPermissionType int8

const (
	ACLPermissionTypeUnknown ACLPermissionType = 0
	ACLPermissionTypeAny     ACLPermissionType = 1
	ACLPermissionTypeDeny    ACLPermissionType = 2
	ACLPermissionTypeAllow   ACLPermissionType = 3
)

type ACLOperationType int8

const (
	ACLOperationTypeUnknown         ACLOperationType = 0
	ACLOperationTypeAny             ACLOperationType = 1
	ACLOperationTypeAll             ACLOperationType = 2
	ACLOperationTypeRead            ACLOperationType = 3
	ACLOperationTypeWrite           ACLOperationType = 4
	ACLOperationTypeCreate          ACLOperationType = 5
	ACLOperationTypeDelete          ACLOperationType = 6
	ACLOperationTypeAlter           ACLOperationType = 7
	ACLOperationTypeDescribe        ACLOperationType = 8
	ACLOperationTypeClusterAction   ACLOperationType = 9
	ACLOperationTypeDescribeConfigs ACLOperationType = 10
	ACLOperationTypeAlterConfigs    ACLOperationType = 11
	ACLOperationTypeIdempotentWrite ACLOperationType = 12
)

type ACLEntry struct {
	ResourceType        ResourceType
	ResourceName        string
	ResourcePatternType PatternType
	Principal           string
	Host                string
	Operation           ACLOperationType
	PermissionType      ACLPermissionType
}

// CreateACLs sends ACLs creation request to a kafka broker and returns the
// response.
func (c *Client) CreateACLs(ctx context.Context, req *CreateACLsRequest) (*CreateACLsResponse, error) {
	acls := make([]createacls.RequestACLs, 0, len(req.ACLs))

	for _, acl := range req.ACLs {
		acls = append(acls, createacls.RequestACLs{
			ResourceType:        int8(acl.ResourceType),
			ResourceName:        acl.ResourceName,
			ResourcePatternType: int8(acl.ResourcePatternType),
			Principal:           acl.Principal,
			Host:                acl.Host,
			Operation:           int8(acl.Operation),
			PermissionType:      int8(acl.PermissionType),
		})
	}

	m, err := c.roundTrip(ctx, req.Addr, &createacls.Request{
		Creations: acls,
	})
	if err != nil {
		return nil, fmt.Errorf("kafka.(*Client).CreateACLs: %w", err)
	}

	res := m.(*createacls.Response)
	ret := &CreateACLsResponse{
		Throttle: makeDuration(res.ThrottleTimeMs),
		Errors:   make([]error, 0, len(res.Results)),
	}

	for _, t := range res.Results {
		ret.Errors = append(ret.Errors, makeError(t.ErrorCode, t.ErrorMessage))
	}

	return ret, nil
}
