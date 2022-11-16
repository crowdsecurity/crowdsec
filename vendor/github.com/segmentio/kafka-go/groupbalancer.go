package kafka

import (
	"sort"
)

// GroupMember describes a single participant in a consumer group.
type GroupMember struct {
	// ID is the unique ID for this member as taken from the JoinGroup response.
	ID string

	// Topics is a list of topics that this member is consuming.
	Topics []string

	// UserData contains any information that the GroupBalancer sent to the
	// consumer group coordinator.
	UserData []byte
}

// GroupMemberAssignments holds MemberID => topic => partitions.
type GroupMemberAssignments map[string]map[string][]int

// GroupBalancer encapsulates the client side rebalancing logic.
type GroupBalancer interface {
	// ProtocolName of the GroupBalancer
	ProtocolName() string

	// UserData provides the GroupBalancer an opportunity to embed custom
	// UserData into the metadata.
	//
	// Will be used by JoinGroup to begin the consumer group handshake.
	//
	// See https://cwiki.apache.org/confluence/display/KAFKA/A+Guide+To+The+Kafka+Protocol#AGuideToTheKafkaProtocol-JoinGroupRequest
	UserData() ([]byte, error)

	// DefineMemberships returns which members will be consuming
	// which topic partitions
	AssignGroups(members []GroupMember, partitions []Partition) GroupMemberAssignments
}

// RangeGroupBalancer groups consumers by partition
//
// Example: 5 partitions, 2 consumers
// 		C0: [0, 1, 2]
// 		C1: [3, 4]
//
// Example: 6 partitions, 3 consumers
// 		C0: [0, 1]
// 		C1: [2, 3]
// 		C2: [4, 5]
//
type RangeGroupBalancer struct{}

func (r RangeGroupBalancer) ProtocolName() string {
	return "range"
}

func (r RangeGroupBalancer) UserData() ([]byte, error) {
	return nil, nil
}

func (r RangeGroupBalancer) AssignGroups(members []GroupMember, topicPartitions []Partition) GroupMemberAssignments {
	groupAssignments := GroupMemberAssignments{}
	membersByTopic := findMembersByTopic(members)

	for topic, members := range membersByTopic {
		partitions := findPartitions(topic, topicPartitions)
		partitionCount := len(partitions)
		memberCount := len(members)

		for memberIndex, member := range members {
			assignmentsByTopic, ok := groupAssignments[member.ID]
			if !ok {
				assignmentsByTopic = map[string][]int{}
				groupAssignments[member.ID] = assignmentsByTopic
			}

			minIndex := memberIndex * partitionCount / memberCount
			maxIndex := (memberIndex + 1) * partitionCount / memberCount

			for partitionIndex, partition := range partitions {
				if partitionIndex >= minIndex && partitionIndex < maxIndex {
					assignmentsByTopic[topic] = append(assignmentsByTopic[topic], partition)
				}
			}
		}
	}

	return groupAssignments
}

// RoundrobinGroupBalancer divides partitions evenly among consumers
//
// Example: 5 partitions, 2 consumers
// 		C0: [0, 2, 4]
// 		C1: [1, 3]
//
// Example: 6 partitions, 3 consumers
// 		C0: [0, 3]
// 		C1: [1, 4]
// 		C2: [2, 5]
//
type RoundRobinGroupBalancer struct{}

func (r RoundRobinGroupBalancer) ProtocolName() string {
	return "roundrobin"
}

func (r RoundRobinGroupBalancer) UserData() ([]byte, error) {
	return nil, nil
}

func (r RoundRobinGroupBalancer) AssignGroups(members []GroupMember, topicPartitions []Partition) GroupMemberAssignments {
	groupAssignments := GroupMemberAssignments{}
	membersByTopic := findMembersByTopic(members)
	for topic, members := range membersByTopic {
		partitionIDs := findPartitions(topic, topicPartitions)
		memberCount := len(members)

		for memberIndex, member := range members {
			assignmentsByTopic, ok := groupAssignments[member.ID]
			if !ok {
				assignmentsByTopic = map[string][]int{}
				groupAssignments[member.ID] = assignmentsByTopic
			}

			for partitionIndex, partition := range partitionIDs {
				if (partitionIndex % memberCount) == memberIndex {
					assignmentsByTopic[topic] = append(assignmentsByTopic[topic], partition)
				}
			}
		}
	}

	return groupAssignments
}

// RackAffinityGroupBalancer makes a best effort to pair up consumers with
// partitions whose leader is in the same rack.  This strategy can have
// performance benefits by minimizing round trip latency between the consumer
// and the broker.  In environments where network traffic across racks incurs
// charges (such as cross AZ data transfer in AWS), this strategy is also a cost
// optimization measure because it keeps network traffic within the local rack
// where possible.
//
// The primary objective is to spread partitions evenly across consumers with a
// secondary focus on maximizing the number of partitions where the leader and
// the consumer are in the same rack.  For best affinity, it's recommended to
// have a balanced spread of consumers and partition leaders across racks.
//
// This balancer requires Kafka version 0.10.0.0+ or later.  Earlier versions do
// not return the brokers' racks in the metadata request.
type RackAffinityGroupBalancer struct {
	// Rack is the name of the rack where this consumer is running.  It will be
	// communicated to the consumer group leader via the UserData so that
	// assignments can be made with affinity to the partition leader.
	Rack string
}

func (r RackAffinityGroupBalancer) ProtocolName() string {
	return "rack-affinity"
}

func (r RackAffinityGroupBalancer) AssignGroups(members []GroupMember, partitions []Partition) GroupMemberAssignments {
	membersByTopic := make(map[string][]GroupMember)
	for _, m := range members {
		for _, t := range m.Topics {
			membersByTopic[t] = append(membersByTopic[t], m)
		}
	}

	partitionsByTopic := make(map[string][]Partition)
	for _, p := range partitions {
		partitionsByTopic[p.Topic] = append(partitionsByTopic[p.Topic], p)
	}

	assignments := GroupMemberAssignments{}
	for topic := range membersByTopic {
		topicAssignments := r.assignTopic(membersByTopic[topic], partitionsByTopic[topic])
		for member, parts := range topicAssignments {
			memberAssignments, ok := assignments[member]
			if !ok {
				memberAssignments = make(map[string][]int)
				assignments[member] = memberAssignments
			}
			memberAssignments[topic] = parts
		}
	}
	return assignments
}

func (r RackAffinityGroupBalancer) UserData() ([]byte, error) {
	return []byte(r.Rack), nil
}

func (r *RackAffinityGroupBalancer) assignTopic(members []GroupMember, partitions []Partition) map[string][]int {
	zonedPartitions := make(map[string][]int)
	for _, part := range partitions {
		zone := part.Leader.Rack
		zonedPartitions[zone] = append(zonedPartitions[zone], part.ID)
	}

	zonedConsumers := make(map[string][]string)
	for _, member := range members {
		zone := string(member.UserData)
		zonedConsumers[zone] = append(zonedConsumers[zone], member.ID)
	}

	targetPerMember := len(partitions) / len(members)
	remainder := len(partitions) % len(members)
	assignments := make(map[string][]int)

	// assign as many as possible in zone.  this will assign up to partsPerMember
	// to each consumer.  it will also prefer to allocate remainder partitions
	// in zone if possible.
	for zone, parts := range zonedPartitions {
		consumers := zonedConsumers[zone]
		if len(consumers) == 0 {
			continue
		}

		// don't over-allocate.  cap partition assignments at the calculated
		// target.
		partsPerMember := len(parts) / len(consumers)
		if partsPerMember > targetPerMember {
			partsPerMember = targetPerMember
		}

		for _, consumer := range consumers {
			assignments[consumer] = append(assignments[consumer], parts[:partsPerMember]...)
			parts = parts[partsPerMember:]
		}

		// if we had enough partitions for each consumer in this zone to hit its
		// target, attempt to use any leftover partitions to satisfy the total
		// remainder by adding at most 1 partition per consumer.
		leftover := len(parts)
		if partsPerMember == targetPerMember {
			if leftover > remainder {
				leftover = remainder
			}
			if leftover > len(consumers) {
				leftover = len(consumers)
			}
			remainder -= leftover
		}

		// this loop covers the case where we're assigning extra partitions or
		// if there weren't enough to satisfy the targetPerMember and the zoned
		// partitions didn't divide evenly.
		for i := 0; i < leftover; i++ {
			assignments[consumers[i]] = append(assignments[consumers[i]], parts[i])
		}
		parts = parts[leftover:]

		if len(parts) == 0 {
			delete(zonedPartitions, zone)
		} else {
			zonedPartitions[zone] = parts
		}
	}

	// assign out remainders regardless of zone.
	var remaining []int
	for _, partitions := range zonedPartitions {
		remaining = append(remaining, partitions...)
	}

	for _, member := range members {
		assigned := assignments[member.ID]
		delta := targetPerMember - len(assigned)
		// if it were possible to assign the remainder in zone, it's been taken
		// care of already.  now we will portion out any remainder to a member
		// that can take it.
		if delta >= 0 && remainder > 0 {
			delta++
			remainder--
		}
		if delta > 0 {
			assignments[member.ID] = append(assigned, remaining[:delta]...)
			remaining = remaining[delta:]
		}
	}

	return assignments
}

// findPartitions extracts the partition ids associated with the topic from the
// list of Partitions provided.
func findPartitions(topic string, partitions []Partition) []int {
	var ids []int
	for _, partition := range partitions {
		if partition.Topic == topic {
			ids = append(ids, partition.ID)
		}
	}
	return ids
}

// findMembersByTopic groups the memberGroupMetadata by topic.
func findMembersByTopic(members []GroupMember) map[string][]GroupMember {
	membersByTopic := map[string][]GroupMember{}
	for _, member := range members {
		for _, topic := range member.Topics {
			membersByTopic[topic] = append(membersByTopic[topic], member)
		}
	}

	// normalize ordering of members to enabling grouping across topics by partitions
	//
	// Want:
	// 		C0 [T0/P0, T1/P0]
	// 		C1 [T0/P1, T1/P1]
	//
	// Not:
	// 		C0 [T0/P0, T1/P1]
	// 		C1 [T0/P1, T1/P0]
	//
	// Even though the later is still round robin, the partitions are crossed
	//
	for _, members := range membersByTopic {
		sort.Slice(members, func(i, j int) bool {
			return members[i].ID < members[j].ID
		})
	}

	return membersByTopic
}

// findGroupBalancer returns the GroupBalancer with the specified protocolName
// from the slice provided.
func findGroupBalancer(protocolName string, balancers []GroupBalancer) (GroupBalancer, bool) {
	for _, balancer := range balancers {
		if balancer.ProtocolName() == protocolName {
			return balancer, true
		}
	}
	return nil, false
}
