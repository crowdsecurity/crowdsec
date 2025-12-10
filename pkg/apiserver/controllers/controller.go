package controllers

import (
	"net"
	"net/http"
	"strings"

	"github.com/alexliesenfeld/health"

	v1 "github.com/crowdsecurity/crowdsec/pkg/apiserver/controllers/v1"
	"github.com/crowdsecurity/crowdsec/pkg/apiserver/router"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/logging"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type Controller struct {
	DBClient                      *database.Client
	Router                        *router.Router
	Profiles                      []*csconfig.ProfileCfg
	AlertsAddChan                 chan []*models.Alert
	DecisionDeleteChan            chan []*models.Decision
	PluginChannel                 chan models.ProfileAlert
	Log                           logging.ExtLogger
	ConsoleConfig                 *csconfig.ConsoleConfig
	TrustedIPs                    []net.IPNet
	HandlerV1                     *v1.Controller
	AutoRegisterCfg               *csconfig.LocalAPIAutoRegisterCfg
	DisableRemoteLapiRegistration bool
}

func (c *Controller) Init() error {
	if err := c.NewV1(); err != nil {
		return err
	}

	/* if we have a V2, just add

	if err := c.NewV2(); err != nil {
		return err
	}

	*/

	return nil
}

// endpoint for health checking
func serveHealth() http.HandlerFunc {
	checker := health.NewChecker(
		// just simple up/down status is enough
		health.WithDisabledDetails(),
		// no caching required
		health.WithDisabledCache(),
	)

	return health.NewHandler(checker)
}

// eitherAuthMiddleware creates a middleware that uses JWT or API key based on request headers
func eitherAuthMiddleware(jwtMiddleware router.Middleware, apiKeyMiddleware router.Middleware) router.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Determine which auth method to use based on headers
			switch {
			case r.Header.Get("X-Api-Key") != "":
				// Use API key middleware
				apiKeyMiddleware(next).ServeHTTP(w, r)
			case r.Header.Get("Authorization") != "":
				// Use JWT middleware
				jwtMiddleware(next).ServeHTTP(w, r)
			case strings.HasPrefix(r.UserAgent(), "crowdsec/"):
				// Guess log processors by sniffing user-agent - use JWT
				jwtMiddleware(next).ServeHTTP(w, r)
			default:
				// Default to API key
				apiKeyMiddleware(next).ServeHTTP(w, r)
			}
		})
	}
}

func (c *Controller) NewV1() error {
	var err error

	v1Config := v1.ControllerV1Config{
		DbClient:           c.DBClient,
		ProfilesCfg:        c.Profiles,
		DecisionDeleteChan: c.DecisionDeleteChan,
		AlertsAddChan:      c.AlertsAddChan,
		PluginChannel:      c.PluginChannel,
		ConsoleConfig:      *c.ConsoleConfig,
		TrustedIPs:         c.TrustedIPs,
		AutoRegisterCfg:    c.AutoRegisterCfg,
	}

	c.HandlerV1, err = v1.New(&v1Config)
	if err != nil {
		return err
	}

	// Register health endpoint
	c.Router.HandleFunc("/health", http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
		serveHealth()(w, r)
	})

	// Apply global middleware
	c.Router.Use(v1.PrometheusMiddleware())
	// Note: Gzip decompression middleware is already applied in apiserver.NewServer()
	// Note: Method not allowed and 404 handling will be done by http.ServeMux

	groupV1 := c.Router.Group("/v1")

	// Apply AbortRemoteIf middleware for /watchers endpoint
	abortMiddleware := c.HandlerV1.AbortRemoteIf(c.DisableRemoteLapiRegistration)
	watchersGroup := groupV1.Group("")
	watchersGroup.Use(abortMiddleware)
	watchersGroup.HandleFunc("/watchers", http.MethodPost, c.HandlerV1.CreateMachine)

	groupV1.HandleFunc("/watchers/login", http.MethodPost, c.HandlerV1.Middlewares.JWT.LoginHandler)

	jwtAuth := groupV1.Group("")
	jwtAuth.HandleFunc("/refresh_token", http.MethodGet, c.HandlerV1.Middlewares.JWT.RefreshHandler)
	jwtAuth.Use(c.HandlerV1.Middlewares.JWT.MiddlewareFunc(), v1.PrometheusMachinesMiddleware())

	// JWT authenticated routes - convert :param to {param} format for Go 1.22+
	jwtAuth.HandleFunc("/alerts", http.MethodPost, c.HandlerV1.CreateAlert)
	jwtAuth.HandleFunc("/alerts", http.MethodGet, c.HandlerV1.FindAlerts)
	jwtAuth.HandleFunc("/alerts", http.MethodHead, c.HandlerV1.FindAlerts)
	jwtAuth.HandleFunc("/alerts/{alert_id}", http.MethodGet, c.HandlerV1.FindAlertByID)
	jwtAuth.HandleFunc("/alerts/{alert_id}", http.MethodHead, c.HandlerV1.FindAlertByID)
	jwtAuth.HandleFunc("/alerts/{alert_id}", http.MethodDelete, c.HandlerV1.DeleteAlertByID)
	jwtAuth.HandleFunc("/alerts", http.MethodDelete, c.HandlerV1.DeleteAlerts)
	jwtAuth.HandleFunc("/decisions", http.MethodDelete, c.HandlerV1.DeleteDecisions)
	jwtAuth.HandleFunc("/decisions/{decision_id}", http.MethodDelete, c.HandlerV1.DeleteDecisionById)
	jwtAuth.HandleFunc("/heartbeat", http.MethodGet, c.HandlerV1.HeartBeat)
	jwtAuth.HandleFunc("/allowlists", http.MethodGet, c.HandlerV1.GetAllowlists)
	jwtAuth.HandleFunc("/allowlists/{allowlist_name}", http.MethodGet, c.HandlerV1.GetAllowlist)
	jwtAuth.HandleFunc("/allowlists/check/{ip_or_range}", http.MethodGet, c.HandlerV1.CheckInAllowlist)
	jwtAuth.HandleFunc("/allowlists/check/{ip_or_range}", http.MethodHead, c.HandlerV1.CheckInAllowlist)
	jwtAuth.HandleFunc("/allowlists/check", http.MethodPost, c.HandlerV1.CheckInAllowlistBulk)
	jwtAuth.HandleFunc("/watchers/self", http.MethodDelete, c.HandlerV1.DeleteMachine)

	apiKeyAuth := groupV1.Group("")
	apiKeyAuth.Use(c.HandlerV1.Middlewares.APIKey.MiddlewareFunc(), v1.PrometheusBouncersMiddleware())
	apiKeyAuth.HandleFunc("/decisions", http.MethodGet, c.HandlerV1.GetDecision)
	apiKeyAuth.HandleFunc("/decisions", http.MethodHead, c.HandlerV1.GetDecision)
	apiKeyAuth.HandleFunc("/decisions/stream", http.MethodGet, c.HandlerV1.StreamDecision)
	apiKeyAuth.HandleFunc("/decisions/stream", http.MethodHead, c.HandlerV1.StreamDecision)

	eitherAuth := groupV1.Group("")
	eitherAuth.Use(eitherAuthMiddleware(c.HandlerV1.Middlewares.JWT.MiddlewareFunc(), c.HandlerV1.Middlewares.APIKey.MiddlewareFunc()))
	eitherAuth.HandleFunc("/usage-metrics", http.MethodPost, c.HandlerV1.UsageMetrics)

	return nil
}

/*
func (c *Controller) NewV2() error {
	handlerV2, err := v2.New(c.DBClient, c.Ectx)
	if err != nil {
		return err
	}

	v2 := c.Router.Group("/v2")
	v2.POST("/watchers", handlerV2.CreateMachine)
	v2.POST("/watchers/login", handlerV2.Middlewares.JWT.Middleware.LoginHandler)

	jwtAuth := v2.Group("")
	jwtAuth.GET("/refresh_token", handlerV2.Middlewares.JWT.Middleware.RefreshHandler)
	jwtAuth.Use(handlerV2.Middlewares.JWT.Middleware.MiddlewareFunc())
	{
		jwtAuth.POST("/alerts", handlerV2.CreateAlert)
		jwtAuth.GET("/alerts", handlerV2.FindAlerts)
		jwtAuth.DELETE("/alerts", handlerV2.DeleteAlerts)
		jwtAuth.DELETE("/decisions", handlerV2.DeleteDecisions)
		jwtAuth.DELETE("/decisions/:decision_id", handlerV2.DeleteDecisionById)
	}

	apiKeyAuth := v2.Group("")
	apiKeyAuth.Use(handlerV2.Middlewares.APIKey.MiddlewareFuncV2())
	{
		apiKeyAuth.GET("/decisions", handlerV2.GetDecision)
		apiKeyAuth.GET("/decisions/stream", handlerV2.StreamDecision)
	}

	return nil
}

*/
