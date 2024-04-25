package dumps

import (
	"io"
	"os"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	"gopkg.in/yaml.v3"
)

type BucketPourInfo map[string][]types.Event

func LoadBucketPourDump(filepath string) (*BucketPourInfo, error) {
	dumpData, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer dumpData.Close()

	results, err := io.ReadAll(dumpData)
	if err != nil {
		return nil, err
	}

	var bucketDump BucketPourInfo

	if err := yaml.Unmarshal(results, &bucketDump); err != nil {
		return nil, err
	}

	return &bucketDump, nil
}
