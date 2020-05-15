package types

import (
	"time"

	"github.com/jinzhu/gorm"
)

//BanApplication is the in-db representation of a ban order. IPs/Ranges are represented as a integer interval.
//one BanOrder can lead to multiple BanApplication
type BanApplication struct {
	gorm.Model `json:"-"`

	MeasureSource string    /*api,local*/
	MeasureType   string    /*ban,slow,captcha*/
	MeasureExtra  string    /*in case we need extra info for the connector ?*/
	Until         time.Time /*expiration of ban*/

	StartIp uint32
	EndIp   uint32

	TargetCN     string
	TargetAS     int
	TargetASName string

	IpText string /*only for humans*/

	Reason   string /*long human reason of the ban 'ban AS1234' */
	Scenario string /*the type of scenario that led to ban*/

	//SignalOccurence   *parser.SignalOccurence /*the signal occurence it's attached to */
	SignalOccurenceID uint //so we can link local decision to actual overflow

}
