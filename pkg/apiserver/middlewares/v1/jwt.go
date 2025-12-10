package v1

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-openapi/strfmt"
	jwtv4 "github.com/golang-jwt/jwt/v4"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver/router"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/machine"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type machineIDKey struct{}

var MachineIDKey = machineIDKey{}

type authInput struct {
	machineID      string
	clientMachine  *ent.Machine
	scenariosInput []string
}

// randomSecret generates a cryptographically secure random secret
func randomSecret() ([]byte, error) {
	size := 64
	secret := make([]byte, size)
	n, err := rand.Read(secret)
	if err != nil {
		return nil, errors.New("unable to generate a new random seed for JWT generation")
	}
	if n != size {
		return nil, errors.New("not enough entropy at random seed generation for JWT generation")
	}
	return secret, nil
}

// JWT is the JWT middleware implementation using golang-jwt/jwt/v4
type JWT struct {
	secret        []byte
	dbClient      *database.Client
	tlsAuth       *TLSAuth
	timeout       time.Duration
	maxRefresh    time.Duration
	tokenLookup   []string // e.g., ["header: Authorization", "query: token", "cookie: jwt"]
	tokenHeadName string   // e.g., "Bearer"
}

type jwtClaims struct {
	jwtv4.RegisteredClaims
	MachineID *string `json:"id"`
}

// NewJWT creates a new JWT middleware using golang-jwt/jwt/v4
func NewJWT(dbClient *database.Client) (*JWT, error) {
	var (
		secret []byte
		err    error
	)

	// Get secret from environment variable
	secretString := os.Getenv("CS_LAPI_SECRET")
	secret = []byte(secretString)

	switch l := len(secret); {
	case l == 0:
		secret, err = randomSecret()
		if err != nil {
			return nil, err
		}
	case l < 64:
		return nil, errors.New("CS_LAPI_SECRET not strong enough")
	}

	return &JWT{
		secret:        secret,
		dbClient:      dbClient,
		tlsAuth:       &TLSAuth{},
		timeout:       time.Hour,
		maxRefresh:    time.Hour,
		tokenLookup:   []string{"header: Authorization", "query: token", "cookie: jwt"},
		tokenHeadName: "Bearer",
	}, nil
}

// SetTlsAuth sets the TLS auth instance for the JWT middleware
func (j *JWT) SetTlsAuth(tlsAuth *TLSAuth) {
	j.tlsAuth = tlsAuth
}

// extractToken extracts the JWT token from the request
// It checks header, query parameter, and cookie as configured
func (j *JWT) extractToken(r *http.Request) (string, error) {
	for _, lookup := range j.tokenLookup {
		parts := strings.Split(lookup, ":")
		if len(parts) != 2 {
			continue
		}

		source := strings.TrimSpace(parts[0])
		name := strings.TrimSpace(parts[1])

		switch source {
		case "header":
			token := r.Header.Get(name)
			if token != "" {
				// Remove token head name (e.g., "Bearer ")
				if j.tokenHeadName != "" && strings.HasPrefix(token, j.tokenHeadName+" ") {
					return strings.TrimPrefix(token, j.tokenHeadName+" "), nil
				}
				return token, nil
			}
		case "query":
			token := r.URL.Query().Get(name)
			if token != "" {
				return token, nil
			}
		case "cookie":
			cookie, err := r.Cookie(name)
			if err == nil {
				if cookie.Value == "" {
					return "", errors.New("cookie token is empty")
				}
				return cookie.Value, nil
			}
		}
	}

	return "", errors.New("token not found")
}

// parseToken parses and validates a JWT token
func (j *JWT) parseToken(tokenString string) (*jwtClaims, error) {
	token, err := jwtv4.ParseWithClaims(tokenString, &jwtClaims{}, func(token *jwtv4.Token) (any, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwtv4.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.secret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*jwtClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token claims")
}

// generateToken generates a new JWT token for the given machine ID
func (j *JWT) generateToken(machineID string) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(j.timeout)

	claims := &jwtClaims{
		RegisteredClaims: jwtv4.RegisteredClaims{
			ExpiresAt: jwtv4.NewNumericDate(expiresAt),
			IssuedAt:  jwtv4.NewNumericDate(now),
			NotBefore: jwtv4.NewNumericDate(now),
		},
		MachineID: &machineID,
	}

	token := jwtv4.NewWithClaims(jwtv4.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(j.secret)
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expiresAt, nil
}

// refreshToken refreshes an existing token if it's within the refresh window
func (j *JWT) refreshToken(tokenString string) (string, time.Time, error) {
	claims, err := j.parseToken(tokenString)
	if err != nil {
		return "", time.Time{}, err
	}

	// Check if token is within refresh window
	now := time.Now()
	if claims.ExpiresAt != nil {
		expiresAt := claims.ExpiresAt.Time
		refreshDeadline := expiresAt.Add(j.maxRefresh)
		if now.After(refreshDeadline) {
			return "", time.Time{}, errors.New("token refresh deadline exceeded")
		}
	}

	// Generate new token with same machine ID
	if claims.MachineID == nil {
		return "", time.Time{}, errors.New("token missing machine ID")
	}

	return j.generateToken(*claims.MachineID)
}

// authTLS handles TLS-based authentication
func (j *JWT) authTLS(r *http.Request, clientIP string) (*authInput, error) {
	if j.tlsAuth == nil {
		return nil, errors.New("tls authentication required")
	}

	extractedCN, err := j.tlsAuth.ValidateCertFromRequest(r)
	if err != nil {
		log.Warn(err)
		return nil, err
	}

	logger := log.WithField("ip", clientIP)
	ret := authInput{}

	ret.machineID = fmt.Sprintf("%s@%s", extractedCN, clientIP)

	ctx := r.Context()
	ret.clientMachine, err = j.dbClient.Ent.Machine.Query().
		Where(machine.MachineId(ret.machineID)).
		First(ctx)
	if ent.IsNotFound(err) {
		// Machine was not found, let's create it
		logger.Infof("machine %s not found, create it", ret.machineID)
		pwd, err := GenerateAPIKey(dummyAPIKeySize)
		if err != nil {
			logger.WithField("cn", extractedCN).
				Errorf("error generating password: %s", err)
			return nil, errors.New("error generating password")
		}

		password := strfmt.Password(pwd)
		ret.clientMachine, err = j.dbClient.CreateMachine(ctx, &ret.machineID, &password, "", true, true, types.TlsAuthType)
		if err != nil {
			return nil, fmt.Errorf("while creating machine entry for %s: %w", ret.machineID, err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("while selecting machine entry for %s: %w", ret.machineID, err)
	} else {
		if ret.clientMachine.AuthType != types.TlsAuthType {
			return nil, fmt.Errorf("machine %s attempted to auth with TLS cert but it is configured to use %s", ret.machineID, ret.clientMachine.AuthType)
		}
		ret.machineID = ret.clientMachine.MachineId
	}

	loginInput := struct {
		Scenarios []string `json:"scenarios"`
	}{
		Scenarios: []string{},
	}

	if err := router.BindJSON(r, &loginInput); err != nil {
		return nil, fmt.Errorf("missing scenarios list in login request for TLS auth: %w", err)
	}

	ret.scenariosInput = loginInput.Scenarios
	return &ret, nil
}

// authPlain handles password-based authentication
func (j *JWT) authPlain(r *http.Request) (*authInput, error) {
	var loginInput models.WatcherAuthRequest
	ret := authInput{}

	if err := router.BindJSON(r, &loginInput); err != nil {
		return nil, fmt.Errorf("missing: %w", err)
	}

	if err := loginInput.Validate(strfmt.Default); err != nil {
		return nil, err
	}

	ret.machineID = *loginInput.MachineID
	password := *loginInput.Password
	ret.scenariosInput = loginInput.Scenarios

	ctx := r.Context()
	var err error
	ret.clientMachine, err = j.dbClient.Ent.Machine.Query().
		Where(machine.MachineId(ret.machineID)).
		First(ctx)
	if err != nil {
		log.Infof("Error machine login for %s : %+v ", ret.machineID, err)
		if ent.IsNotFound(err) {
			// Return generic error for security (don't reveal if machine exists)
			return nil, errors.New("incorrect Username or Password")
		}
		return nil, err
	}

	if ret.clientMachine == nil {
		log.Errorf("Nothing for '%s'", ret.machineID)
		return nil, errors.New("incorrect Username or Password")
	}

	if ret.clientMachine.AuthType != types.PasswordAuthType {
		return nil, fmt.Errorf("machine %s attempted to auth with password but it is configured to use %s", ret.machineID, ret.clientMachine.AuthType)
	}

	if !ret.clientMachine.IsValidated {
		return nil, fmt.Errorf("machine %s not validated", ret.machineID)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(ret.clientMachine.Password), []byte(password)); err != nil {
		return nil, errors.New("incorrect Username or Password")
	}

	return &ret, nil
}

// authenticator performs authentication and returns the authenticated machine ID
func (j *JWT) authenticator(r *http.Request, clientIP string) (string, error) {
	var (
		err  error
		auth *authInput
	)

	ctx := r.Context()

	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		auth, err = j.authTLS(r, clientIP)
		if err != nil {
			return "", err
		}
	} else {
		auth, err = j.authPlain(r)
		if err != nil {
			return "", err
		}
	}

	var scenarios string
	if len(auth.scenariosInput) > 0 {
		scenarios = strings.Join(auth.scenariosInput, ",")
		err = j.dbClient.UpdateMachineScenarios(ctx, scenarios, auth.clientMachine.ID)
		if err != nil {
			log.Errorf("Failed to update scenarios list for '%s': %s\n", auth.machineID, err)
			return "", errors.New("failed authentication")
		}
	}

	if auth.clientMachine.IpAddress == "" {
		err = j.dbClient.UpdateMachineIP(ctx, clientIP, auth.clientMachine.ID)
		if err != nil {
			log.Errorf("Failed to update ip address for '%s': %s\n", auth.machineID, err)
			return "", errors.New("failed authentication")
		}
	}

	if auth.clientMachine.IpAddress != clientIP && auth.clientMachine.IpAddress != "" {
		log.Warningf("new IP address detected for machine '%s': %s (old: %s)", auth.clientMachine.MachineId, clientIP, auth.clientMachine.IpAddress)
		err = j.dbClient.UpdateMachineIP(ctx, clientIP, auth.clientMachine.ID)
		if err != nil {
			log.Errorf("Failed to update ip address for '%s': %s\n", auth.clientMachine.MachineId, err)
			return "", errors.New("failed authentication")
		}
	}

	useragent := strings.Split(r.UserAgent(), "/")
	if len(useragent) != 2 {
		log.Warningf("bad user agent '%s' from '%s'", r.UserAgent(), clientIP)
		return "", errors.New("failed authentication")
	}

	if err := j.dbClient.UpdateMachineVersion(ctx, useragent[1], auth.clientMachine.ID); err != nil {
		log.Errorf("unable to update machine '%s' version '%s': %s", auth.clientMachine.MachineId, useragent[1], err)
		return "", errors.New("failed authentication")
	}

	return auth.machineID, nil
}

// LoginHandler handles login requests and returns a JWT token
func (j *JWT) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		router.AbortWithStatus(w, http.StatusMethodNotAllowed)
		return
	}

	clientIP := router.GetClientIP(r) // Gets IP from context (resolved by ClientIPMiddleware)
	machineID, err := j.authenticator(r, clientIP)
	if err != nil {
		router.AbortWithJSON(w, http.StatusUnauthorized, map[string]any{
			"code":    http.StatusUnauthorized,
			"message": err.Error(),
		})
		return
	}

	tokenString, expiresAt, err := j.generateToken(machineID)
	if err != nil {
		router.AbortWithJSON(w, http.StatusInternalServerError, map[string]any{
			"code":    http.StatusInternalServerError,
			"message": "failed to generate token",
		})
		return
	}

	response := models.WatcherAuthResponse{
		Token:  tokenString,
		Expire: expiresAt.Format(time.RFC3339),
	}

	router.WriteJSON(w, http.StatusOK, response)
}

// RefreshHandler handles token refresh requests
func (j *JWT) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		router.AbortWithStatus(w, http.StatusMethodNotAllowed)
		return
	}

	tokenString, err := j.extractToken(r)
	if err != nil {
		router.AbortWithJSON(w, http.StatusUnauthorized, map[string]any{
			"code":    http.StatusUnauthorized,
			"message": err.Error(),
		})
		return
	}

	newTokenString, expiresAt, err := j.refreshToken(tokenString)
	if err != nil {
		router.AbortWithJSON(w, http.StatusUnauthorized, map[string]any{
			"code":    http.StatusUnauthorized,
			"message": err.Error(),
		})
		return
	}

	response := models.WatcherAuthResponse{
		Token:  newTokenString,
		Expire: expiresAt.Format(time.RFC3339),
	}

	router.WriteJSON(w, http.StatusOK, response)
}

// MiddlewareFunc returns a middleware that validates JWT tokens
func (j *JWT) MiddlewareFunc() router.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString, err := j.extractToken(r)
			if err != nil {
				router.AbortWithJSON(w, http.StatusUnauthorized, map[string]any{
					"code":    http.StatusUnauthorized,
					"message": err.Error(),
				})
				return
			}

			claims, err := j.parseToken(tokenString)
			if err != nil {
				router.AbortWithJSON(w, http.StatusUnauthorized, map[string]any{
					"code":    http.StatusUnauthorized,
					"message": "invalid token",
				})
				return
			}

			if claims.MachineID == nil {
				router.AbortWithJSON(w, http.StatusUnauthorized, map[string]any{
					"code":    http.StatusUnauthorized,
					"message": "token missing machine ID",
				})
				return
			}

			// Store machine ID in request context
			ctx := context.WithValue(r.Context(), MachineIDKey, *claims.MachineID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetMachineIDFromRequest extracts the machine ID from the request context
func GetMachineIDFromRequest(r *http.Request) (string, error) {
	machineID, ok := r.Context().Value(MachineIDKey).(string)
	if !ok || machineID == "" {
		return "", errors.New("machine ID not found in request context")
	}
	return machineID, nil
}
