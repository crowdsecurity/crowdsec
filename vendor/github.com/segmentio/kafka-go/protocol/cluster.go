package protocol

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
)

type Cluster struct {
	ClusterID  string
	Controller int32
	Brokers    map[int32]Broker
	Topics     map[string]Topic
}

func (c Cluster) BrokerIDs() []int32 {
	brokerIDs := make([]int32, 0, len(c.Brokers))
	for id := range c.Brokers {
		brokerIDs = append(brokerIDs, id)
	}
	sort.Slice(brokerIDs, func(i, j int) bool {
		return brokerIDs[i] < brokerIDs[j]
	})
	return brokerIDs
}

func (c Cluster) TopicNames() []string {
	topicNames := make([]string, 0, len(c.Topics))
	for name := range c.Topics {
		topicNames = append(topicNames, name)
	}
	sort.Strings(topicNames)
	return topicNames
}

func (c Cluster) IsZero() bool {
	return c.ClusterID == "" && c.Controller == 0 && len(c.Brokers) == 0 && len(c.Topics) == 0
}

func (c Cluster) Format(w fmt.State, _ rune) {
	tw := new(tabwriter.Writer)
	fmt.Fprintf(w, "CLUSTER: %q\n\n", c.ClusterID)

	tw.Init(w, 0, 8, 2, ' ', 0)
	fmt.Fprint(tw, "  BROKER\tHOST\tPORT\tRACK\tCONTROLLER\n")

	for _, id := range c.BrokerIDs() {
		broker := c.Brokers[id]
		fmt.Fprintf(tw, "  %d\t%s\t%d\t%s\t%t\n", broker.ID, broker.Host, broker.Port, broker.Rack, broker.ID == c.Controller)
	}

	tw.Flush()
	fmt.Fprintln(w)

	tw.Init(w, 0, 8, 2, ' ', 0)
	fmt.Fprint(tw, "  TOPIC\tPARTITIONS\tBROKERS\n")
	topicNames := c.TopicNames()
	brokers := make(map[int32]struct{}, len(c.Brokers))
	brokerIDs := make([]int32, 0, len(c.Brokers))

	for _, name := range topicNames {
		topic := c.Topics[name]

		for _, p := range topic.Partitions {
			for _, id := range p.Replicas {
				brokers[id] = struct{}{}
			}
		}

		for id := range brokers {
			brokerIDs = append(brokerIDs, id)
		}

		fmt.Fprintf(tw, "  %s\t%d\t%s\n", topic.Name, len(topic.Partitions), formatBrokerIDs(brokerIDs, -1))

		for id := range brokers {
			delete(brokers, id)
		}

		brokerIDs = brokerIDs[:0]
	}

	tw.Flush()
	fmt.Fprintln(w)

	if w.Flag('+') {
		for _, name := range topicNames {
			fmt.Fprintf(w, "  TOPIC: %q\n\n", name)

			tw.Init(w, 0, 8, 2, ' ', 0)
			fmt.Fprint(tw, "    PARTITION\tREPLICAS\tISR\tOFFLINE\n")

			for _, p := range c.Topics[name].Partitions {
				fmt.Fprintf(tw, "    %d\t%s\t%s\t%s\n", p.ID,
					formatBrokerIDs(p.Replicas, -1),
					formatBrokerIDs(p.ISR, p.Leader),
					formatBrokerIDs(p.Offline, -1),
				)
			}

			tw.Flush()
			fmt.Fprintln(w)
		}
	}
}

func formatBrokerIDs(brokerIDs []int32, leader int32) string {
	if len(brokerIDs) == 0 {
		return ""
	}

	if len(brokerIDs) == 1 {
		return itoa(brokerIDs[0])
	}

	sort.Slice(brokerIDs, func(i, j int) bool {
		id1 := brokerIDs[i]
		id2 := brokerIDs[j]

		if id1 == leader {
			return true
		}

		if id2 == leader {
			return false
		}

		return id1 < id2
	})

	brokerNames := make([]string, len(brokerIDs))

	for i, id := range brokerIDs {
		brokerNames[i] = itoa(id)
	}

	return strings.Join(brokerNames, ",")
}

var (
	_ fmt.Formatter = Cluster{}
)
