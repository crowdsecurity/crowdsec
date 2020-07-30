package database

import (
	"testing"
	"time"
)

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
