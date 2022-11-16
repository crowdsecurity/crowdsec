package kafka

// https://github.com/apache/kafka/blob/trunk/clients/src/main/java/org/apache/kafka/common/resource/ResourceType.java
type ResourceType int8

const (
	ResourceTypeUnknown ResourceType = 0
	ResourceTypeAny     ResourceType = 1
	ResourceTypeTopic   ResourceType = 2
	ResourceTypeGroup   ResourceType = 3
	// See https://github.com/apache/kafka/blob/trunk/clients/src/main/java/org/apache/kafka/common/config/ConfigResource.java#L36
	ResourceTypeBroker          ResourceType = 4
	ResourceTypeCluster         ResourceType = 4
	ResourceTypeTransactionalID ResourceType = 5
	ResourceTypeDelegationToken ResourceType = 6
)

// https://github.com/apache/kafka/blob/trunk/clients/src/main/java/org/apache/kafka/common/resource/PatternType.java
type PatternType int8

const (
	// PatternTypeUnknown represents any PatternType which this client cannot
	// understand.
	PatternTypeUnknown PatternType = 0
	// PatternTypeAny matches any resource pattern type.
	PatternTypeAny PatternType = 1
	// PatternTypeMatch perform pattern matching.
	PatternTypeMatch PatternType = 2
	// PatternTypeLiteral represents a literal name.
	// A literal name defines the full name of a resource, e.g. topic with name
	// 'foo', or group with name 'bob'.
	PatternTypeLiteral PatternType = 3
	// PatternTypePrefixed represents a prefixed name.
	// A prefixed name defines a prefix for a resource, e.g. topics with names
	// that start with 'foo'.
	PatternTypePrefixed PatternType = 4
)
