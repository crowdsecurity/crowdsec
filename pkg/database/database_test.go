package database

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/davecgh/go-spew/spew"
	"github.com/jinzhu/gorm"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
)

type AnyTime struct{}

// Match satisfies sqlmock.Argument interface
func (a AnyTime) Match(v driver.Value) bool {
	_, ok := v.(time.Time)
	return ok
}

var _ = ginkgo.Describe("TestWrites", func() {
	var ctx *Context
	var mock sqlmock.Sqlmock

	ginkgo.BeforeEach(func() {
		var db *sql.DB
		var err error

		db, mock, err = sqlmock.New() // mock sql.DB
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

		gdb, err := gorm.Open("sqlite", db) // open gorm db
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

		ctx = &Context{Db: gdb}
		//ctx.Db.LogMode(true)
	})
	ginkgo.AfterEach(func() {
		err := mock.ExpectationsWereMet() // make sure all expectations were met
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
	})

	ginkgo.Context("insert ban_applications", func() {
		ginkgo.It("insert 1.2.3.4", func() {

			const sqlSelectAll = `SELECT * FROM "ban_applications" WHERE "ban_applications"."deleted_at" IS NULL AND (("ban_applications"."ip_text" = ?)) ORDER BY "ban_applications"."id" ASC LIMIT 1`

			insertBan := types.BanApplication{IpText: "1.2.3.4"}

			mock.ExpectQuery(regexp.QuoteMeta(sqlSelectAll)).WithArgs("1.2.3.4").WillReturnRows(sqlmock.NewRows(nil))

			mock.ExpectBegin()

			const sqlInsertBanApplication = `INSERT INTO "ban_applications" ("created_at","updated_at","deleted_at","measure_source","measure_type","measure_extra","until","start_ip","end_ip","target_cn","target_as","target_as_name","ip_text","reason","scenario","signal_occurence_id") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
			InsertExpectedResult := sqlmock.NewResult(1, 1)
			mock.ExpectExec(regexp.QuoteMeta(sqlInsertBanApplication)).WithArgs(
				AnyTime{},
				AnyTime{},
				nil,
				insertBan.MeasureSource,
				insertBan.MeasureType,
				insertBan.MeasureExtra,
				AnyTime{},
				insertBan.StartIp,
				insertBan.EndIp,
				insertBan.TargetCN,
				insertBan.TargetAS,
				insertBan.TargetASName,
				insertBan.IpText,
				insertBan.Reason,
				insertBan.Scenario,
				insertBan.SignalOccurenceID).WillReturnResult(InsertExpectedResult)

			mock.ExpectCommit()

			err := ctx.WriteBanApplication(insertBan)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		})
	})

	ginkgo.Context("insert signal_occurence", func() {
		ginkgo.It("insert signal+ban for 1.2.3.4", func() {
			insertBan := types.BanApplication{IpText: "1.2.3.4", SignalOccurenceID: 1}
			insertSig := types.SignalOccurence{
				MapKey:                        "ratata",
				Scenario:                      "test_1",
				BanApplications:               []types.BanApplication{insertBan},
				Source_ip:                     "1.2.3.4",
				Source_range:                  "1.2.3.0/24",
				Source_AutonomousSystemNumber: "1234",
			}

			//the part that try to delete pending existing bans
			mock.ExpectBegin()
			const sqlDeleteOldBan = `UPDATE "ban_applications" SET "deleted_at"=?  WHERE "ban_applications"."deleted_at" IS NULL AND ((ip_text = ?))`
			sqlDeleteOldBanResult := sqlmock.NewResult(1, 1)
			mock.ExpectExec(regexp.QuoteMeta(sqlDeleteOldBan)).WithArgs(AnyTime{}, "1.2.3.4").WillReturnResult(sqlDeleteOldBanResult)
			mock.ExpectCommit()

			//insert the signal occurence
			mock.ExpectBegin()
			const sqlInsertNewEvent = `INSERT INTO "signal_occurences" ("created_at","updated_at","deleted_at","map_key","scenario","bucket_id","alert_message","events_count","start_at","stop_at","source_ip","source_range","source_autonomous_system_number","source_autonomous_system_organization","source_country","source_latitude","source_longitude","dest_ip","capacity","leak_speed","reprocess") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
			sqlInsertNewEventResult := sqlmock.NewResult(1, 1)
			mock.ExpectExec(regexp.QuoteMeta(sqlInsertNewEvent)).WithArgs(
				AnyTime{},
				AnyTime{},
				nil,
				insertSig.MapKey,
				insertSig.Scenario,
				"",
				"",
				0,
				AnyTime{},
				AnyTime{},
				insertSig.Source_ip,
				insertSig.Source_range,
				insertSig.Source_AutonomousSystemNumber,
				"",
				"",
				0.0,
				0.0,
				"",
				0,
				0,
				false,
			).WillReturnResult(sqlInsertNewEventResult)

			//insert the ban application
			const sqlInsertBanApplication = `INSERT INTO "ban_applications" ("created_at","updated_at","deleted_at","measure_source","measure_type","measure_extra","until","start_ip","end_ip","target_cn","target_as","target_as_name","ip_text","reason","scenario","signal_occurence_id") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
			sqlInsertBanApplicationResults := sqlmock.NewResult(1, 1)
			mock.ExpectExec(regexp.QuoteMeta(sqlInsertBanApplication)).WithArgs(
				AnyTime{},
				AnyTime{},
				nil,
				insertBan.MeasureSource,
				insertBan.MeasureType,
				insertBan.MeasureExtra,
				AnyTime{},
				insertBan.StartIp,
				insertBan.EndIp,
				insertBan.TargetCN,
				insertBan.TargetAS,
				insertBan.TargetASName,
				insertBan.IpText,
				insertBan.Reason,
				insertBan.Scenario,
				insertBan.SignalOccurenceID).WillReturnResult(sqlInsertBanApplicationResults)

			mock.ExpectCommit()

			err := ctx.WriteSignal(insertSig)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		})
	})

	ginkgo.Context("insert old signal_occurence + cleanup", func() {
		ginkgo.It("insert signal+ban for 1.2.3.4", func() {

			target_ip := net.ParseIP("1.2.3.4")

			OldBan := types.BanApplication{
				MeasureType:   "ban",
				MeasureSource: "local",
				//expired one month ago
				Until:        time.Now().Add(-24 * 30 * time.Hour),
				StartIp:      types.IP2Int(target_ip),
				EndIp:        types.IP2Int(target_ip),
				TargetCN:     "FR",
				TargetAS:     1234,
				TargetASName: "Random AS",
				IpText:       target_ip.String(),
				Reason:       "A reason",
				Scenario:     "A scenario",
			}
			OldSignal := types.SignalOccurence{
				MapKey:   "lala",
				Scenario: "old_overflow",
				//two month ago : 24*60
				Start_at:        time.Now().Add(-24 * 60 * time.Hour),
				Stop_at:         time.Now().Add(-24 * 60 * time.Hour),
				BanApplications: []types.BanApplication{OldBan},
			}

			//the part that try to delete pending existing bans
			mock.ExpectBegin()
			const sqlDeleteOldBan = `UPDATE "ban_applications" SET "deleted_at"=?  WHERE "ban_applications"."deleted_at" IS NULL AND ((ip_text = ?))`
			sqlDeleteOldBanResult := sqlmock.NewResult(1, 1)
			mock.ExpectExec(regexp.QuoteMeta(sqlDeleteOldBan)).WithArgs(AnyTime{}, target_ip.String()).WillReturnResult(sqlDeleteOldBanResult)
			mock.ExpectCommit()

			//insert the signal occurence
			mock.ExpectBegin()
			const sqlInsertNewEvent = `INSERT INTO "signal_occurences" ("created_at","updated_at","deleted_at","map_key","scenario","bucket_id","alert_message","events_count","start_at","stop_at","source_ip","source_range","source_autonomous_system_number","source_autonomous_system_organization","source_country","source_latitude","source_longitude","dest_ip","capacity","leak_speed","reprocess") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
			sqlInsertNewEventResult := sqlmock.NewResult(1, 1)
			mock.ExpectExec(regexp.QuoteMeta(sqlInsertNewEvent)).WithArgs(
				AnyTime{},
				AnyTime{},
				nil,
				OldSignal.MapKey,
				OldSignal.Scenario,
				"",
				"",
				0,
				AnyTime{},
				AnyTime{},
				OldSignal.Source_ip,
				OldSignal.Source_range,
				OldSignal.Source_AutonomousSystemNumber,
				"",
				"",
				0.0,
				0.0,
				"",
				0,
				0,
				false,
			).WillReturnResult(sqlInsertNewEventResult)

			//insert the ban application
			const sqlInsertBanApplication = `INSERT INTO "ban_applications" ("created_at","updated_at","deleted_at","measure_source","measure_type","measure_extra","until","start_ip","end_ip","target_cn","target_as","target_as_name","ip_text","reason","scenario","signal_occurence_id") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
			sqlInsertBanApplicationResults := sqlmock.NewResult(1, 1)
			mock.ExpectExec(regexp.QuoteMeta(sqlInsertBanApplication)).WithArgs(
				AnyTime{},
				AnyTime{},
				nil,
				OldBan.MeasureSource,
				OldBan.MeasureType,
				OldBan.MeasureExtra,
				AnyTime{},
				OldBan.StartIp,
				OldBan.EndIp,
				OldBan.TargetCN,
				OldBan.TargetAS,
				OldBan.TargetASName,
				OldBan.IpText,
				OldBan.Reason,
				OldBan.Scenario,
				1).WillReturnResult(sqlInsertBanApplicationResults)

			mock.ExpectCommit()

			err := ctx.WriteSignal(OldSignal)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

		})
	})

})

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

func TestInsertSqlMock(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "TestWrites")
}

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

func TestInsertOldBans(t *testing.T) {
	//Plan:
	// - flush db
	// - insert month old ban
	// - use GetBansAt on current + past time and check results
	// - @todo : we need to call the DeleteExpired and such

	validCfg := map[string]string{
		"type":            "sqlite",
		"db_path":         "./test.db",
		"max_records":     "1000",
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

	target_ip := net.ParseIP("1.2.3.4")

	OldBan := types.BanApplication{
		MeasureType:   "ban",
		MeasureSource: "local",
		//expired one month ago
		Until:        time.Now().Add(-24 * 30 * time.Hour),
		StartIp:      types.IP2Int(target_ip),
		EndIp:        types.IP2Int(target_ip),
		TargetCN:     "FR",
		TargetAS:     1234,
		TargetASName: "Random AS",
		IpText:       target_ip.String(),
		Reason:       "A reason",
		Scenario:     "A scenario",
	}
	OldSignal := types.SignalOccurence{
		MapKey:   "lala",
		Scenario: "old_overflow",
		//two month ago : 24*60
		Start_at:        time.Now().Add(-24 * 60 * time.Hour),
		Stop_at:         time.Now().Add(-24 * 60 * time.Hour),
		BanApplications: []types.BanApplication{OldBan},
	}
	//write the old signal
	err = ctx.WriteSignal(OldSignal)
	if err != nil {
		t.Fatalf("Failed to insert old signal : %s", err)
	}

	//fetch bans at current time
	bans, err := ctx.GetBansAt(time.Now())
	if err != nil {
		t.Fatalf("failed to get bans : %s", err)
	}

	if len(bans) != 0 {
		fmt.Printf("%s", spew.Sdump(bans))
		t.Fatalf("should not have bans, got %d bans", len(bans))
	}
	//get bans in the past
	bans, err = ctx.GetBansAt(time.Now().Add(-24 * 31 * time.Hour))
	if err != nil {
		t.Fatalf("failed to get bans : %s", err)
	}

	if len(bans) != 1 {
		t.Fatalf("should had 1 ban, got %d bans", len(bans))
	}
	if !reflect.DeepEqual(bans, []map[string]string{map[string]string{
		"source":       "local",
		"until":        "-720h0m0s",
		"reason":       "old_overflow",
		"iptext":       "1.2.3.4",
		"cn":           "",
		"events_count": "0",
		"action":       "ban",
		"as":           " ",
		"bancount":     "0",
		"scenario":     "old_overflow",
	}}) {
		t.Fatalf("unexpected results")
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
