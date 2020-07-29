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

func TestFetchBans(t *testing.T) {
	//Plan:
	// - flush db
	// - write signal+ban for 1.2.3.4
	// - get bans (as a connector) + check
	// - write signal+ban for 1.2.3.5
	// - get new bans (as a connector) + check
	// - delete ban for 1.2.3.4
	// - get deleted bans (as a connector) + check

	validCfg := map[string]string{
		"type":            "sqlite",
		"db_path":         "./test.db",
		"max_records_age": "72h",
		"debug":           "false",
		"flush":           "true",
	}
	ctx, err := NewDatabase(validCfg)
	if err != nil || ctx == nil {
		t.Fatalf("failed to create simple sqlite")
	}

	if err := ctx.DeleteAll(); err != nil {
		t.Fatalf("failed to flush existing bans")
	}

	OldSignal := genSignalOccurence("1.2.3.4")
	//write the old signal
	if err = ctx.WriteSignal(OldSignal); err != nil {
		t.Fatalf("Failed to insert old signal : %s", err)
	}

	//we startup, we should get one ban
	firstFetch := time.Now()
	bans, err := ctx.GetNewBan()
	if len(bans) != 1 {
		t.Fatalf("expected one ban")
	}

	NewSignal := genSignalOccurence("1.2.3.5")

	//write the old signal
	if err = ctx.WriteSignal(NewSignal); err != nil {
		t.Fatalf("Failed to insert old signal : %s", err)
	}

	//we startup, we should get one ban
	bans, err = ctx.GetNewBanSince(firstFetch)
	firstFetch = time.Now()
	if len(bans) != 1 {
		t.Fatal()
	}
	if bans[0].MeasureSource != NewSignal.BanApplications[0].MeasureSource {
		t.Fatal()
	}
	if bans[0].MeasureType != NewSignal.BanApplications[0].MeasureType {
		t.Fatal()
	}
	if bans[0].StartIp != NewSignal.BanApplications[0].StartIp {
		t.Fatal()
	}
	if bans[0].EndIp != NewSignal.BanApplications[0].EndIp {
		t.Fatal()
	}
	if bans[0].Reason != NewSignal.BanApplications[0].Reason {
		t.Fatal()
	}
	//Delete a ban
	count, err := ctx.DeleteBan("1.2.3.4")
	if err != nil {
		t.Fatal()
	}
	if count != 1 {
		t.Fatal()
	}
	//we shouldn't have any new bans
	bans, err = ctx.GetNewBanSince(firstFetch)
	if len(bans) != 0 {
		t.Fatal()
	}
	// //GetDeletedBanSince adds one second to the timestamp. why ? I'm not sure
	// time.Sleep(1 * time.Second)
	//but we should get a deleted ban
	bans, err = ctx.GetDeletedBanSince(firstFetch.Add(-2 * time.Second))
	if len(bans) != 1 {
		t.Fatalf("got %d", len(bans))
	}
	//OldSignal
	if bans[0].MeasureSource != OldSignal.BanApplications[0].MeasureSource {
		t.Fatal()
	}
	if bans[0].MeasureType != OldSignal.BanApplications[0].MeasureType {
		t.Fatal()
	}
	if bans[0].StartIp != OldSignal.BanApplications[0].StartIp {
		t.Fatal()
	}
	if bans[0].EndIp != OldSignal.BanApplications[0].EndIp {
		t.Fatal()
	}
	if bans[0].Reason != OldSignal.BanApplications[0].Reason {
		t.Fatal()
	}
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
