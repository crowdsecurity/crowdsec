package metabase

const (
	dashboardEndpoint          = "dashboard"
	dashboardByIDEndpoint      = "dashboard_by_id"
	addCardToDashboardEndpoint = "add_card_to_dashboard"
	databaseEndpoint           = "add_data_source"
	resetPasswordEndpoint      = "reset_password"
	loginEndpoint              = "login"
	setupEndpoint              = "setup"
	getSessionEndpoint         = "get_session"
	cardsEndpoint              = "card"
	currentUserEndpoint        = "current_user"
	datasetEndpoint            = "dataset"
	queryEndpoint              = "query"
	cardByIDEndpoint           = "card_by_id"
)

var (
	routes = map[string]string{
		dashboardEndpoint:          "api/dashboard",
		addCardToDashboardEndpoint: "api/dashboard/%d/cards",
		databaseEndpoint:           "api/database",
		resetPasswordEndpoint:      "user/1/password",
		loginEndpoint:              "api/session",
		setupEndpoint:              "api/setup",
		getSessionEndpoint:         "api/session/properties",
		dashboardByIDEndpoint:      "api/dashboard/%d",
		cardsEndpoint:              "api/card/",
		currentUserEndpoint:        "api/user/current",
		datasetEndpoint:            "api/dataset",
		queryEndpoint:              "api/card/%d/query",
		cardByIDEndpoint:           "api/card/%d",
	}
)
