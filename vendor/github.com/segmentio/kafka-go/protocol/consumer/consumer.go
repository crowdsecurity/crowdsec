package consumer

const MaxVersionSupported = 1

type Subscription struct {
	Version         int16            `kafka:"min=v0,max=v1"`
	Topics          []string         `kafka:"min=v0,max=v1"`
	UserData        []byte           `kafka:"min=v0,max=v1,nullable"`
	OwnedPartitions []TopicPartition `kafka:"min=v1,max=v1"`
}

type Assignment struct {
	Version            int16            `kafka:"min=v0,max=v1"`
	AssignedPartitions []TopicPartition `kafka:"min=v0,max=v1"`
	UserData           []byte           `kafka:"min=v0,max=v1,nullable"`
}

type TopicPartition struct {
	Topic      string  `kafka:"min=v0,max=v1"`
	Partitions []int32 `kafka:"min=v0,max=v1"`
}
