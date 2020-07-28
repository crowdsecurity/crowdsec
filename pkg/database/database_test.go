package database

import (
	"database/sql"
	"database/sql/driver"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/crowdsecurity/crowdsec/pkg/types"
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
		ctx.Db.LogMode(true)
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
			//mock.ExpectCommit()

			//insert the ban application
			//mock.ExpectBegin()
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

})

func TestSql(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "TestWrites")
}
