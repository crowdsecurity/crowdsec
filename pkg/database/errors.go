package database

import "errors"

var (
	UserExists        = errors.New("user already exist")
	UserNotExists     = errors.New("user doesn't exist")
	HashError         = errors.New("unable to hash")
	InsertFail        = errors.New("unable to insert row")
	QueryFail         = errors.New("unable to query")
	UpdateFail        = errors.New("unable to update")
	DeleteFail        = errors.New("unable to delete")
	ParseTimeFail     = errors.New("unable to parse time")
	ParseDurationFail = errors.New("unable to parse duration")
	MarshalFail       = errors.New("unable to marshal")
	UnmarshalFail     = errors.New("unable to unmarshal")
	BulkError         = errors.New("unable to insert bulk")
	ParseType         = errors.New("unable to parse type")
	InvalidIPOrRange  = errors.New("invalid ip address / range")
	InvalidFilter     = errors.New("invalid filter")
)
