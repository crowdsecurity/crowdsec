package kafka

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

type ApiVersion struct {
	ApiKey     int16
	MinVersion int16
	MaxVersion int16
}

func (v ApiVersion) Format(w fmt.State, r rune) {
	switch r {
	case 's':
		fmt.Fprint(w, apiKey(v.ApiKey))
	case 'd':
		switch {
		case w.Flag('-'):
			fmt.Fprint(w, v.MinVersion)
		case w.Flag('+'):
			fmt.Fprint(w, v.MaxVersion)
		default:
			fmt.Fprint(w, v.ApiKey)
		}
	case 'v':
		switch {
		case w.Flag('-'):
			fmt.Fprintf(w, "v%d", v.MinVersion)
		case w.Flag('+'):
			fmt.Fprintf(w, "v%d", v.MaxVersion)
		case w.Flag('#'):
			fmt.Fprintf(w, "kafka.ApiVersion{ApiKey:%d MinVersion:%d MaxVersion:%d}", v.ApiKey, v.MinVersion, v.MaxVersion)
		default:
			fmt.Fprintf(w, "%s[v%d:v%d]", apiKey(v.ApiKey), v.MinVersion, v.MaxVersion)
		}
	}
}

type apiKey int16

const (
	produce                     apiKey = 0
	fetch                       apiKey = 1
	listOffsets                 apiKey = 2
	metadata                    apiKey = 3
	leaderAndIsr                apiKey = 4
	stopReplica                 apiKey = 5
	updateMetadata              apiKey = 6
	controlledShutdown          apiKey = 7
	offsetCommit                apiKey = 8
	offsetFetch                 apiKey = 9
	findCoordinator             apiKey = 10
	joinGroup                   apiKey = 11
	heartbeat                   apiKey = 12
	leaveGroup                  apiKey = 13
	syncGroup                   apiKey = 14
	describeGroups              apiKey = 15
	listGroups                  apiKey = 16
	saslHandshake               apiKey = 17
	apiVersions                 apiKey = 18
	createTopics                apiKey = 19
	deleteTopics                apiKey = 20
	deleteRecords               apiKey = 21
	initProducerId              apiKey = 22
	offsetForLeaderEpoch        apiKey = 23
	addPartitionsToTxn          apiKey = 24
	addOffsetsToTxn             apiKey = 25
	endTxn                      apiKey = 26
	writeTxnMarkers             apiKey = 27
	txnOffsetCommit             apiKey = 28
	describeAcls                apiKey = 29
	createAcls                  apiKey = 30
	deleteAcls                  apiKey = 31
	describeConfigs             apiKey = 32
	alterConfigs                apiKey = 33
	alterReplicaLogDirs         apiKey = 34
	describeLogDirs             apiKey = 35
	saslAuthenticate            apiKey = 36
	createPartitions            apiKey = 37
	createDelegationToken       apiKey = 38
	renewDelegationToken        apiKey = 39
	expireDelegationToken       apiKey = 40
	describeDelegationToken     apiKey = 41
	deleteGroups                apiKey = 42
	electLeaders                apiKey = 43
	incrementalAlterConfigs     apiKey = 44
	alterPartitionReassignments apiKey = 45
	listPartitionReassignments  apiKey = 46
	offsetDelete                apiKey = 47
)

func (k apiKey) String() string {
	if i := int(k); i >= 0 && i < len(apiKeyStrings) {
		return apiKeyStrings[i]
	}
	return strconv.Itoa(int(k))
}

type apiVersion int16

const (
	v0  = 0
	v1  = 1
	v2  = 2
	v3  = 3
	v5  = 5
	v7  = 7
	v10 = 10

	// Unused protocol versions: v4, v6, v8, v9.
)

var apiKeyStrings = [...]string{
	produce:                     "Produce",
	fetch:                       "Fetch",
	listOffsets:                 "ListOffsets",
	metadata:                    "Metadata",
	leaderAndIsr:                "LeaderAndIsr",
	stopReplica:                 "StopReplica",
	updateMetadata:              "UpdateMetadata",
	controlledShutdown:          "ControlledShutdown",
	offsetCommit:                "OffsetCommit",
	offsetFetch:                 "OffsetFetch",
	findCoordinator:             "FindCoordinator",
	joinGroup:                   "JoinGroup",
	heartbeat:                   "Heartbeat",
	leaveGroup:                  "LeaveGroup",
	syncGroup:                   "SyncGroup",
	describeGroups:              "DescribeGroups",
	listGroups:                  "ListGroups",
	saslHandshake:               "SaslHandshake",
	apiVersions:                 "ApiVersions",
	createTopics:                "CreateTopics",
	deleteTopics:                "DeleteTopics",
	deleteRecords:               "DeleteRecords",
	initProducerId:              "InitProducerId",
	offsetForLeaderEpoch:        "OffsetForLeaderEpoch",
	addPartitionsToTxn:          "AddPartitionsToTxn",
	addOffsetsToTxn:             "AddOffsetsToTxn",
	endTxn:                      "EndTxn",
	writeTxnMarkers:             "WriteTxnMarkers",
	txnOffsetCommit:             "TxnOffsetCommit",
	describeAcls:                "DescribeAcls",
	createAcls:                  "CreateAcls",
	deleteAcls:                  "DeleteAcls",
	describeConfigs:             "DescribeConfigs",
	alterConfigs:                "AlterConfigs",
	alterReplicaLogDirs:         "AlterReplicaLogDirs",
	describeLogDirs:             "DescribeLogDirs",
	saslAuthenticate:            "SaslAuthenticate",
	createPartitions:            "CreatePartitions",
	createDelegationToken:       "CreateDelegationToken",
	renewDelegationToken:        "RenewDelegationToken",
	expireDelegationToken:       "ExpireDelegationToken",
	describeDelegationToken:     "DescribeDelegationToken",
	deleteGroups:                "DeleteGroups",
	electLeaders:                "ElectLeaders",
	incrementalAlterConfigs:     "IncrementalAlfterConfigs",
	alterPartitionReassignments: "AlterPartitionReassignments",
	listPartitionReassignments:  "ListPartitionReassignments",
	offsetDelete:                "OffsetDelete",
}

type requestHeader struct {
	Size          int32
	ApiKey        int16
	ApiVersion    int16
	CorrelationID int32
	ClientID      string
}

func (h requestHeader) size() int32 {
	return 4 + 2 + 2 + 4 + sizeofString(h.ClientID)
}

func (h requestHeader) writeTo(wb *writeBuffer) {
	wb.writeInt32(h.Size)
	wb.writeInt16(h.ApiKey)
	wb.writeInt16(h.ApiVersion)
	wb.writeInt32(h.CorrelationID)
	wb.writeString(h.ClientID)
}

type request interface {
	size() int32
	writable
}

func makeInt8(b []byte) int8 {
	return int8(b[0])
}

func makeInt16(b []byte) int16 {
	return int16(binary.BigEndian.Uint16(b))
}

func makeInt32(b []byte) int32 {
	return int32(binary.BigEndian.Uint32(b))
}

func makeInt64(b []byte) int64 {
	return int64(binary.BigEndian.Uint64(b))
}

func expectZeroSize(sz int, err error) error {
	if err == nil && sz != 0 {
		err = fmt.Errorf("reading a response left %d unread bytes", sz)
	}
	return err
}
