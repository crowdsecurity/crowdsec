package metabase

const (
	dashboardEndpoint     = "dashboard"
	dashboardByIDEndpoint = "dashboard_by_id"
	addCardToDashboard    = "add_card_to_dashboard"
	databaseEndpoint      = "add_data_source"
	resetPassword         = "reset_password"
	login                 = "login"
	setup                 = "setup"
	getSession            = "get_session"
	cardsEndpoint         = "card"
	currentUser           = "current_user"
	datasetEndpoint       = "dataset"
	queryEndpoint         = "query"
	cardByIDEndpoint      = "card_by_id"
)

var (
	routes = map[string]string{
		dashboardEndpoint:     "api/dashboard",
		addCardToDashboard:    "api/dashboard/%d/cards",
		databaseEndpoint:      "api/database",
		resetPassword:         "user/1/password",
		login:                 "api/session",
		setup:                 "api/setup",
		getSession:            "api/session/properties",
		dashboardByIDEndpoint: "api/dashboard/%d",
		cardsEndpoint:         "api/card/",
		currentUser:           "api/user/current",
		datasetEndpoint:       "api/dataset",
		queryEndpoint:         "api/card/%d/query",
		cardByIDEndpoint:      "api/card/%d",
	}
)
