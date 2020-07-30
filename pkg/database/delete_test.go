package database

import (
	"fmt"
	"testing"
	"time"
)

func TestNoCleanUpParams(t *testing.T) {
	validCfg := map[string]string{
		"type":            "sqlite",
		"db_path":         "./test.db",
		"debug":           "false",
		"max_records":     "0",
		"max_records_age": "0s",
		"flush":           "true",
	}
	ctx, err := NewDatabase(validCfg)
	if err != nil || ctx == nil {
		t.Fatalf("failed to create simple sqlite")
	}

	if err := ctx.DeleteAll(); err != nil {
		t.Fatalf("failed to flush existing bans")
	}

	freshRecordsCount := 12

	for i := 0; i < freshRecordsCount; i++ {
		//this one expires in the future
		OldSignal := genSignalOccurence(fmt.Sprintf("2.2.2.%d", i))

		OldSignal.BanApplications[0].Until = time.Now().Add(1 * time.Hour)
		if err = ctx.WriteBanApplication(OldSignal.BanApplications[0]); err != nil {
			t.Fatalf("Failed to insert old signal : %s", err)
		}
	}

	bans, err := ctx.GetBansAt(time.Now())
	if err != nil {
		t.Fatalf("%s", err)
	}
	if len(bans) != freshRecordsCount {
		t.Fatalf("expected %d, got %d", freshRecordsCount, len(bans))
	}

	//Cleanup by age should hard delete old records
	deleted, err := ctx.CleanUpRecordsByCount()
	if err != nil {
		t.Fatalf("error %s", err)
	}
	if deleted != 0 {
		t.Fatalf("unexpected %d deleted events", deleted)
	}

	//Cleanup by age should hard delete old records
	deleted, err = ctx.CleanUpRecordsByAge()
	if err != nil {
		t.Fatalf("error %s", err)
	}
	if deleted != 0 {
		t.Fatalf("unexpected %d deleted events ", deleted)
	}

}

func TestNoCleanUp(t *testing.T) {
	validCfg := map[string]string{
		"type":            "sqlite",
		"db_path":         "./test.db",
		"debug":           "false",
		"max_records":     "1000",
		"max_records_age": "24h",
		"flush":           "true",
	}
	ctx, err := NewDatabase(validCfg)
	if err != nil || ctx == nil {
		t.Fatalf("failed to create simple sqlite")
	}

	if err := ctx.DeleteAll(); err != nil {
		t.Fatalf("failed to flush existing bans")
	}

	freshRecordsCount := 12

	for i := 0; i < freshRecordsCount; i++ {
		//this one expires in the future
		OldSignal := genSignalOccurence(fmt.Sprintf("2.2.2.%d", i))

		OldSignal.BanApplications[0].Until = time.Now().Add(1 * time.Hour)
		if err = ctx.WriteBanApplication(OldSignal.BanApplications[0]); err != nil {
			t.Fatalf("Failed to insert old signal : %s", err)
		}
	}

	bans, err := ctx.GetBansAt(time.Now())
	if err != nil {
		t.Fatalf("%s", err)
	}
	if len(bans) != freshRecordsCount {
		t.Fatalf("expected %d, got %d", freshRecordsCount, len(bans))
	}

	//Cleanup by age should hard delete old records
	deleted, err := ctx.CleanUpRecordsByCount()
	if err != nil {
		t.Fatalf("error %s", err)
	}
	if deleted != 0 {
		t.Fatalf("unexpected %d deleted events", deleted)
	}

	//Cleanup by age should hard delete old records
	deleted, err = ctx.CleanUpRecordsByAge()
	if err != nil {
		t.Fatalf("error %s", err)
	}
	if deleted != 0 {
		t.Fatalf("unexpected %d deleted events ", deleted)
	}

}

func TestBanOnly(t *testing.T) {
	validCfg := map[string]string{
		"type":    "sqlite",
		"db_path": "./test.db",
		"debug":   "false",
		"flush":   "true",
	}
	ctx, err := NewDatabase(validCfg)
	if err != nil || ctx == nil {
		t.Fatalf("failed to create simple sqlite")
	}

	if err := ctx.DeleteAll(); err != nil {
		t.Fatalf("failed to flush existing bans")
	}

	freshRecordsCount := 12

	for i := 0; i < freshRecordsCount; i++ {
		//this one expires in the future
		OldSignal := genSignalOccurence(fmt.Sprintf("2.2.2.%d", i))

		OldSignal.BanApplications[0].Until = time.Now().Add(1 * time.Hour)
		if err = ctx.WriteBanApplication(OldSignal.BanApplications[0]); err != nil {
			t.Fatalf("Failed to insert old signal : %s", err)
		}
	}

	bans, err := ctx.GetBansAt(time.Now())
	if err != nil {
		t.Fatalf("%s", err)
	}
	if len(bans) != freshRecordsCount {
		t.Fatalf("expected %d, got %d", freshRecordsCount, len(bans))
	}
}

func TestCleanUpByCount(t *testing.T) {
	//plan :
	// - insert one current event
	// - insert 150 old events
	// - check DeletedExpired behavior
	// - check CleanUpByCount behavior

	maxCount := 72
	validCfg := map[string]string{
		"type":    "sqlite",
		"db_path": "./test.db",
		//that's 15 days
		"max_records": fmt.Sprintf("%d", maxCount),
		"debug":       "false",
		"flush":       "true",
	}
	ctx, err := NewDatabase(validCfg)
	if err != nil || ctx == nil {
		t.Fatalf("failed to create simple sqlite")
	}

	if err := ctx.DeleteAll(); err != nil {
		t.Fatalf("failed to flush existing bans")
	}

	freshRecordsCount := 12

	for i := 0; i < freshRecordsCount; i++ {
		//this one expires in the future
		OldSignal := genSignalOccurence(fmt.Sprintf("2.2.2.%d", i))
		OldSignal.BanApplications[0].Until = time.Now().Add(1 * time.Hour)
		if err = ctx.WriteSignal(OldSignal); err != nil {
			t.Fatalf("Failed to insert old signal : %s", err)
		}
	}

	oldRecordsCount := 136

	for i := 0; i < oldRecordsCount; i++ {
		OldSignal := genSignalOccurence(fmt.Sprintf("1.2.3.%d", i))
		//let's make the event a month old
		OldSignal.Start_at = time.Now().Add(-30 * 24 * time.Hour)
		OldSignal.Stop_at = time.Now().Add(-30 * 24 * time.Hour)
		//ban was like for an hour
		OldSignal.BanApplications[0].Until = time.Now().Add(-30*24*time.Hour + 1*time.Hour)
		//write the old signal
		if err = ctx.WriteSignal(OldSignal); err != nil {
			t.Fatalf("Failed to insert old signal : %s", err)
		}
	}

	evtsCount := 0
	ret := ctx.Db.Unscoped().Table("ban_applications").Count(&evtsCount)
	if ret.Error != nil {
		t.Fatalf("got err : %s", ret.Error)
	}
	if evtsCount != oldRecordsCount+freshRecordsCount {
		t.Fatalf("got %d events", evtsCount)
	}

	//if we call DeleteExpired, it will soft deleted those events in the past

	softDeleted, err := ctx.DeleteExpired()

	if err != nil {
		t.Fatalf("%s", err)
	}

	if softDeleted != oldRecordsCount {
		t.Fatalf("%d deleted records", softDeleted)
	}

	//we should be left with *one* non-deleted record
	evtsCount = 0
	ret = ctx.Db.Table("ban_applications").Where("deleted_at is NULL").Count(&evtsCount)
	if ret.Error != nil {
		t.Fatalf("got err : %s", ret.Error)
	}
	if evtsCount != freshRecordsCount {
		t.Fatalf("got %d events", evtsCount)
	}

	evtsCount = 0
	ret = ctx.Db.Table("ban_applications").Where("deleted_at is not NULL").Count(&evtsCount)
	if ret.Error != nil {
		t.Fatalf("got err : %s", ret.Error)
	}
	if evtsCount != oldRecordsCount {
		t.Fatalf("got %d events", evtsCount)
	}

	//ctx.Db.LogMode(true)

	//Cleanup by age should hard delete old records
	deleted, err := ctx.CleanUpRecordsByCount()
	if err != nil {
		t.Fatalf("error %s", err)
	}
	if deleted != (oldRecordsCount+freshRecordsCount)-maxCount {
		t.Fatalf("unexpected %d deleted events (expected: %d)", deleted, oldRecordsCount-maxCount)
	}

	//and now we should have *one* record left !
	evtsCount = 0
	ret = ctx.Db.Unscoped().Table("ban_applications").Count(&evtsCount)
	if ret.Error != nil {
		t.Fatalf("got err : %s", ret.Error)
	}
	if evtsCount != maxCount {
		t.Fatalf("got %d events", evtsCount)
	}
}

func TestCleanUpByAge(t *testing.T) {
	//plan :
	// - insert one current event
	// - insert 150 old events
	// - check DeletedExpired behavior
	// - check CleanUpByAge behavior

	validCfg := map[string]string{
		"type":    "sqlite",
		"db_path": "./test.db",
		//that's 15 days
		"max_records_age": "360h",
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

	freshRecordsCount := 8

	for i := 0; i < freshRecordsCount; i++ {
		//this one expires in the future
		OldSignal := genSignalOccurence(fmt.Sprintf("2.2.2.%d", i))
		OldSignal.BanApplications[0].Until = time.Now().Add(1 * time.Hour)
		if err = ctx.WriteSignal(OldSignal); err != nil {
			t.Fatalf("Failed to insert old signal : %s", err)
		}
	}

	oldRecordsCount := 150

	for i := 0; i < oldRecordsCount; i++ {
		OldSignal := genSignalOccurence(fmt.Sprintf("1.2.3.%d", i))
		//let's make the event a month old
		OldSignal.Start_at = time.Now().Add(-30 * 24 * time.Hour)
		OldSignal.Stop_at = time.Now().Add(-30 * 24 * time.Hour)
		//ban was like for an hour
		OldSignal.BanApplications[0].Until = time.Now().Add(-30*24*time.Hour + 1*time.Hour)
		//write the old signal
		if err = ctx.WriteSignal(OldSignal); err != nil {
			t.Fatalf("Failed to insert old signal : %s", err)
		}
	}

	evtsCount := 0
	ret := ctx.Db.Unscoped().Table("ban_applications").Count(&evtsCount)
	if ret.Error != nil {
		t.Fatalf("got err : %s", ret.Error)
	}
	if evtsCount != oldRecordsCount+freshRecordsCount {
		t.Fatalf("got %d events", evtsCount)
	}

	//if we call DeleteExpired, it will soft deleted those events in the past

	softDeleted, err := ctx.DeleteExpired()

	if err != nil {
		t.Fatalf("%s", err)
	}

	if softDeleted != oldRecordsCount {
		t.Fatalf("%d deleted records", softDeleted)
	}

	//we should be left with *one* non-deleted record
	evtsCount = 0
	ret = ctx.Db.Table("ban_applications").Where("deleted_at is NULL").Count(&evtsCount)
	if ret.Error != nil {
		t.Fatalf("got err : %s", ret.Error)
	}
	if evtsCount != freshRecordsCount {
		t.Fatalf("got %d events", evtsCount)
	}

	evtsCount = 0
	ret = ctx.Db.Table("ban_applications").Where("deleted_at is not NULL").Count(&evtsCount)
	if ret.Error != nil {
		t.Fatalf("got err : %s", ret.Error)
	}
	if evtsCount != oldRecordsCount {
		t.Fatalf("got %d events", evtsCount)
	}

	//Cleanup by age should hard delete old records
	deleted, err := ctx.CleanUpRecordsByAge()
	if deleted != oldRecordsCount {
		t.Fatalf("unexpected %d deleted events", deleted)
	}

	//and now we should have *one* record left !
	evtsCount = 0
	ret = ctx.Db.Unscoped().Table("ban_applications").Count(&evtsCount)
	if ret.Error != nil {
		t.Fatalf("got err : %s", ret.Error)
	}
	if evtsCount != freshRecordsCount {
		t.Fatalf("got %d events", evtsCount)
	}
}
