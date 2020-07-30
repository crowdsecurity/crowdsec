package database

import (
	"net"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func genSignalOccurence(ip string) types.SignalOccurence {
	target_ip := net.ParseIP(ip)

	Ban := types.BanApplication{
		MeasureType:   "ban",
		MeasureSource: "local",
		//for 10 minutes
		Until:        time.Now().Add(10 * time.Minute),
		StartIp:      types.IP2Int(target_ip),
		EndIp:        types.IP2Int(target_ip),
		TargetCN:     "FR",
		TargetAS:     1234,
		TargetASName: "Random AS",
		IpText:       target_ip.String(),
		Reason:       "A reason",
		Scenario:     "A scenario",
	}
	Signal := types.SignalOccurence{
		MapKey:   "lala",
		Scenario: "old_overflow",
		//a few minutes ago
		Start_at:        time.Now().Add(-10 * time.Minute),
		Stop_at:         time.Now().Add(-5 * time.Minute),
		BanApplications: []types.BanApplication{Ban},
	}
	return Signal
}

func TestCreateDB(t *testing.T) {

	var CfgTests = []struct {
		cfg   map[string]string
		valid bool
	}{
		{map[string]string{
			"type":            "sqlite",
			"db_path":         "./test.db",
			"max_records":     "1000",
			"max_records_age": "72h",
			"debug":           "false",
			"flush":           "true",
		}, true},

		//bad type
		{map[string]string{
			"type":        "inexistant_DB",
			"db_path":     "./test.db",
			"max_records": "1000",
			"debug":       "false",
			"flush":       "true",
		}, false},

		//missing db_path
		{map[string]string{
			"type":        "sqlite",
			"max_records": "1000",
			"debug":       "false",
			"flush":       "true",
		}, false},

		//valid mysql, but won't be able to connect and thus fail
		{map[string]string{
			"type":        "mysql",
			"db_host":     "localhost",
			"db_username": "crowdsec",
			"db_password": "password",
			"db_name":     "crowdsec",
			"max_records": "1000",
			"debug":       "false",
			"flush":       "true",
		}, false},

		//mysql : missing host
		{map[string]string{
			"type":        "mysql",
			"db_username": "crowdsec",
			"db_password": "password",
			"db_name":     "crowdsec",
			"max_records": "1000",
			"debug":       "false",
			"flush":       "true",
		}, false},

		//mysql : missing username
		{map[string]string{
			"type":        "mysql",
			"db_host":     "localhost",
			"db_password": "password",
			"db_name":     "crowdsec",
			"max_records": "1000",
			"debug":       "false",
			"flush":       "true",
		}, false},

		//mysql : missing password
		{map[string]string{
			"type":        "mysql",
			"db_host":     "localhost",
			"db_username": "crowdsec",
			"db_name":     "crowdsec",
			"max_records": "1000",
			"debug":       "false",
			"flush":       "true",
		}, false},

		//mysql : missing db_name
		{map[string]string{
			"type":        "mysql",
			"db_host":     "localhost",
			"db_username": "crowdsec",
			"db_password": "password",
			"max_records": "1000",
			"debug":       "false",
			"flush":       "true",
		}, false},

		//sqlite : bad bools
		{map[string]string{
			"type":            "sqlite",
			"db_path":         "./test.db",
			"max_records":     "1000",
			"max_records_age": "72h",
			"debug":           "false",
			"flush":           "ratata",
		}, false},
	}

	for idx, TestCase := range CfgTests {
		ctx, err := NewDatabase(TestCase.cfg)
		if TestCase.valid {
			if err != nil {
				t.Fatalf("didn't expect error (case %d/%d) : %s", idx, len(CfgTests), err)
			}
			if ctx == nil {
				t.Fatalf("didn't expect empty ctx (case %d/%d)", idx, len(CfgTests))
			}
		} else {
			if err == nil {
				t.Fatalf("expected error (case %d/%d)", idx, len(CfgTests))
			}
			if ctx != nil {
				t.Fatalf("expected nil ctx (case %d/%d)", idx, len(CfgTests))
			}
		}
	}

}
