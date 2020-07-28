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
	log "github.com/sirupsen/logrus"
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

	ginkgo.Context("insert ban", func() {
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

			//"2020-07-28 13:52:27","2020-07-28 13:52:27",NULL,'','','','0000-00-00 00:00:00',0,0,'',0,'','1\\.2\\.3\\.4','','',0\\)').WillReturnRows(sqlmock.NewRows(nil))
			mock.ExpectCommit()

			err := ctx.WriteBanApplication(types.BanApplication{IpText: "1.2.3.4"})
			if err != nil {
				log.Printf("err -> %s", err)
			}
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		})
	})
	// It("test something", func(){
	//     ...
	// })
})

func TestSql(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "TestWrites")
}

// // a successful case
// func TestInsertDatabase(t *testing.T) {

// 	db, mock, err := sqlmock.New()
// 	if err != nil {
// 		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
// 	}
// 	defer db.Close()

// 	fakeCtx := Context{Db: db}

// 	mock.ExpectBegin()
// 	mock.ExpectExec("UPDATE products").WillReturnResult(sqlmock.NewResult(1, 1))
// 	mock.ExpectExec("INSERT INTO product_viewers").WithArgs(2, 3).WillReturnResult(sqlmock.NewResult(1, 1))
// 	mock.ExpectCommit()

// 	// now we execute our method
// 	if err = recordStats(db, 2, 3); err != nil {
// 		t.Errorf("error was not expected while updating stats: %s", err)
// 	}

// 	// we make sure that all expectations were met
// 	if err := mock.ExpectationsWereMet(); err != nil {
// 		t.Errorf("there were unfulfilled expectations: %s", err)
// 	}
// }
