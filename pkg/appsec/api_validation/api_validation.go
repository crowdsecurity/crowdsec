package apivalidation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	legacyrouter "github.com/getkin/kin-openapi/routers/legacy"
	"github.com/golang-jwt/jwt/v4" // We use v4 because gin-jwt uses it
	log "github.com/sirupsen/logrus"
)

const (
	ExtensionJWKSURI = "x-crowdsec-jwks_uri"
)

var (
	ErrInvalidSchemaName = errors.New("invalid schema name")
)

// ValidationError provides detailed information about validation failures
type ValidationError struct {
	Reason        string
	Field         string
	SchemaPath    string
	Message       string
	Value         string
	Expected      string
	OriginalError error
}

func (ve *ValidationError) Error() string {
	if ve.Field != "" {
		return fmt.Sprintf("%s: field '%s' %s", ve.Reason, ve.Field, ve.Message)
	}
	return fmt.Sprintf("%s: %s", ve.Reason, ve.Message)
}

type SchemaData struct {
	Schema *openapi3.T
	Router routers.Router
}

type RequestValidator struct {
	loaders        map[string]*openapi3.Loader
	openAPISchemas map[string]SchemaData
	logger         *log.Entry
}

func NewRequestValidator(logger *log.Entry) *RequestValidator {
	return &RequestValidator{
		loaders:        make(map[string]*openapi3.Loader),
		openAPISchemas: make(map[string]SchemaData),
		logger:         logger,
	}
}

func (rv *RequestValidator) validateJWTToken(token string, jwksURI string) error {
	rv.logger.Debugf("validating JWT token with JWKS URI %s", jwksURI)

	_, err := jwt.Parse(token, nil)
	if err != nil {
		return fmt.Errorf("invalid JWT token: %v", err)
	}

	return nil
}

func (rv *RequestValidator) authFunc(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
	authTokenValue := ""
	switch input.SecurityScheme.Type {
	case "http":
		switch input.SecurityScheme.Scheme {
		case "basic":
			values := input.RequestValidationInput.Request.Header["Authorization"]
			if len(values) == 0 {
				return fmt.Errorf("authorization header not found")
			}
			if len(values) > 1 {
				return fmt.Errorf("multiple Authorization headers found")
			}
			if !strings.HasPrefix(values[0], "Basic ") {
				return fmt.Errorf("authorization header does not start with 'Basic '")
			}
			authTokenValue = values[0][6:]
		case "bearer":
			values := input.RequestValidationInput.Request.Header["Authorization"]
			if len(values) == 0 {
				return fmt.Errorf("authorization header not found")
			}
			if len(values) > 1 {
				return fmt.Errorf("multiple Authorization headers found")
			}
			if !strings.HasPrefix(values[0], "Bearer ") {
				return fmt.Errorf("authorization header does not start with 'Bearer '")
			}
			authTokenValue = values[0][7:]
		}
	case "apiKey":
		switch input.SecurityScheme.In {
		case "query":
			//FIXME: we probably want a more lax version
			values := input.RequestValidationInput.Request.URL.Query()[input.SecurityScheme.Name]
			if len(values) == 0 {
				return fmt.Errorf("query parameter %s not found", input.SecurityScheme.Name)
			}
			if len(values) > 1 {
				return fmt.Errorf("multiple query parameters with name %s found", input.SecurityScheme.Name)
			}
			authTokenValue = values[0]
		case "header":
			canonicalHeaderName := http.CanonicalHeaderKey(input.SecurityScheme.Name)
			values := input.RequestValidationInput.Request.Header[canonicalHeaderName]
			if len(values) == 0 {
				return fmt.Errorf("header %s not found", input.SecurityScheme.Name)
			}
			if len(values) > 1 {
				return fmt.Errorf("multiple headers with name %s found", input.SecurityScheme.Name)
			}
			authTokenValue = values[0]
		case "cookie":
			cookieValues := input.RequestValidationInput.Request.CookiesNamed(input.SecurityScheme.Name)
			if len(cookieValues) == 0 {
				return fmt.Errorf("cookie %s not found", input.SecurityScheme.Name)
			}
			if len(cookieValues) > 1 {
				return fmt.Errorf("multiple cookies with name %s found", input.SecurityScheme.Name)
			}
			authTokenValue = cookieValues[0].Value
		default:
			return fmt.Errorf("unsupported apiKey location %s", input.SecurityScheme.In)
		}
	case "oauth2":
		rv.logger.Warnf("oauth2 security scheme not supported")
	case "openIdConnect":
		rv.logger.Warnf("openIdConnect security scheme not supported")
	default:
		return fmt.Errorf("unsupported security scheme type %s", input.SecurityScheme.Type)
	}
	if authTokenValue == "" {
		return fmt.Errorf("auth token is required but not provided")
	}

	// If a JWKS URI is provided, attempt to validate the token
	jwksURI := input.SecurityScheme.Extensions[ExtensionJWKSURI]
	if jwksURI == nil {
		// no JWKS URI, we can't validate the token
		return nil
	}
	jwksURIStr, ok := jwksURI.(string)
	if !ok {
		return fmt.Errorf("invalid JWKS URI, expected string: %v", jwksURI)
	}

	if err := rv.validateJWTToken(authTokenValue, jwksURIStr); err != nil {
		return err
	}

	return nil
}

func (rv *RequestValidator) LoadSchema(ref string, schema string) error {
	if ref == "" {
		return fmt.Errorf("ref cannot be empty")
	}
	rv.logger.Debugf("loading schema for ref %s", ref)

	if _, exists := rv.loaders[ref]; exists {
		return fmt.Errorf("attempting to load a new schema for existing ref %s", ref)
	}

	loader := openapi3.NewLoader()
	rv.loaders[ref] = loader

	doc, err := loader.LoadFromData([]byte(schema))
	if err != nil {
		return err
	}

	// Is it a valid OpenAPI schema?
	// FIXME: look into opts
	if err := doc.Validate(loader.Context, openapi3.DisableExamplesValidation()); err != nil {
		return err
	}

	router, err := legacyrouter.NewRouter(doc)
	if err != nil {
		return fmt.Errorf("failed to create router for schema ref %s: %w", ref, err)
	}

	rv.openAPISchemas[ref] = SchemaData{
		Schema: doc,
		Router: router,
	}

	rv.logger.Infof("loaded schema for ref %s", ref)
	return nil
}

func (rv *RequestValidator) ValidateRequest(ctx context.Context, ref string, r *http.Request) error {
	schemaData, exists := rv.openAPISchemas[ref]
	if !exists {
		return fmt.Errorf("%w: no schema loaded for ref %s", ErrInvalidSchemaName, ref)
	}

	rv.logger.Debugf("validating request for ref %s", ref)

	route, pathParam, err := schemaData.Router.FindRoute(r)
	if err != nil {
		//FIXME: allow the user to configure the behavior if no matching route is found:
		// - Ignore the error and return
		// - Drop the request

		// From the kin-openapi package:
		// // ErrPathNotFound is returned when no route match is found
		// var ErrPathNotFound error = &RouteError{"no matching operation was found"}

		// ErrMethodNotAllowed is returned when no method of the matched route matches
		//var ErrMethodNotAllowed error = &RouteError{"method not allowed"}

		return fmt.Errorf("failed to find route for request: %w (error type: %T)", err, err)
	}

	input := &openapi3filter.RequestValidationInput{
		Request:     r,
		QueryParams: r.URL.Query(), //FIXME: we probably want a more lax version
		Route:       route,
		PathParams:  pathParam,
		Options: &openapi3filter.Options{
			// If true, all validation errors are returned. Should we stop at the 1st one ?
			// Having to deal with multiple error will make creating a user-friendly event harder
			MultiError:         false,
			AuthenticationFunc: rv.authFunc,
		},
	}

	//FIXME: this will automatically parse the request body
	// The supported content types are:
	//// 	RegisterBodyDecoder("application/json", JSONBodyDecoder)
	//RegisterBodyDecoder("application/json-patch+json", JSONBodyDecoder)
	//RegisterBodyDecoder("application/ld+json", JSONBodyDecoder)
	//RegisterBodyDecoder("application/hal+json", JSONBodyDecoder)
	//RegisterBodyDecoder("application/vnd.api+json", JSONBodyDecoder)
	//RegisterBodyDecoder("application/octet-stream", FileBodyDecoder)
	//RegisterBodyDecoder("application/problem+json", JSONBodyDecoder)
	//RegisterBodyDecoder("application/x-www-form-urlencoded", urlencodedBodyDecoder)
	//RegisterBodyDecoder("application/x-yaml", yamlBodyDecoder)
	//RegisterBodyDecoder("application/yaml", yamlBodyDecoder)
	//RegisterBodyDecoder("application/zip", zipFileBodyDecoder)
	//RegisterBodyDecoder("multipart/form-data", multipartBodyDecoder)
	//RegisterBodyDecoder("text/csv", csvBodyDecoder)
	//RegisterBodyDecoder("text/plain", plainBodyDecoder)

	// THe zip decoder seems a bit dangerous, as it does not seem to have protection against zip bombs
	// Let's just disable it for now, we'll see what we want to do when the vuln is fixed
	openapi3filter.UnregisterBodyDecoder("application/zip")

	err = openapi3filter.ValidateRequest(ctx, input)
	if err == nil {
		return nil
	}

	requestError := &openapi3filter.RequestError{}
	if errors.As(err, &requestError) {
		return rv.parseRequestError(requestError)
	}

	securityRequirementError := &openapi3filter.SecurityRequirementsError{}
	if errors.As(err, &securityRequirementError) {
		return rv.parseSecurityError(securityRequirementError)
	}

	rv.logger.Debugf("request validation error: %s (type %T)", err.Error(), err)
	return err
}

// parseRequestError extracts detailed information from openapi3filter.RequestError
func (rv *RequestValidator) parseRequestError(reqErr *openapi3filter.RequestError) error {
	ve := &ValidationError{
		OriginalError: reqErr,
	}

	switch {
	case reqErr.Parameter != nil:
		ve.Reason = "parameter"
		ve.Field = reqErr.Parameter.Name
		if reqErr.Input != nil && reqErr.Input.Request != nil {
			ve.SchemaPath = fmt.Sprintf("/paths%s/parameters/%s", reqErr.Input.Request.URL.Path, reqErr.Parameter.Name)
		}
		ve.Message = reqErr.Err.Error()
		ve.Expected = getSchemaTypeInfo(reqErr.Parameter.Schema)

		if reqErr.Input != nil && reqErr.Input.Request != nil {
			switch reqErr.Parameter.In {
			case "query":
				ve.Value = truncateString(reqErr.Input.Request.URL.Query().Get(reqErr.Parameter.Name), 100)
			case "header":
				ve.Value = truncateString(reqErr.Input.Request.Header.Get(reqErr.Parameter.Name), 100)
			case "path":
				// Path params are in RequestValidationInput.PathParams
				if reqErr.Input.PathParams != nil {
					if val, ok := reqErr.Input.PathParams[reqErr.Parameter.Name]; ok {
						ve.Value = truncateString(val, 100)
					}
				}
			case "cookie":
				if cookie, err := reqErr.Input.Request.Cookie(reqErr.Parameter.Name); err == nil {
					ve.Value = truncateString(cookie.Value, 100)
				}
			}
		}

	case reqErr.RequestBody != nil:
		ve.Reason = "request_body"
		if reqErr.Input != nil && reqErr.Input.Request != nil {
			ve.SchemaPath = fmt.Sprintf("/paths%s/%s/requestBody", reqErr.Input.Request.URL.Path, strings.ToLower(reqErr.Input.Request.Method))
		}
		ve.Message = reqErr.Err.Error()

		ve.Field = extractFieldFromSchemaError(reqErr.Err)
		ve.Expected = "valid request body according to schema"
		ve.Value = "<request body>"

	default:
		// Generic request error
		ve.Reason = "request"
		ve.Message = reqErr.Err.Error()
		if reqErr.Input != nil && reqErr.Input.Request != nil {
			ve.SchemaPath = reqErr.Input.Request.URL.Path
		}
	}

	rv.logger.WithFields(log.Fields{
		"reason":      ve.Reason,
		"field":       ve.Field,
		"schema_path": ve.SchemaPath,
		"message":     ve.Message,
		"expected":    ve.Expected,
		"value":       ve.Value,
	}).Debug("validation error details")

	return ve
}

func (rv *RequestValidator) parseSecurityError(secErr *openapi3filter.SecurityRequirementsError) error {
	ve := &ValidationError{
		Reason:        "security",
		OriginalError: secErr,
	}

	if len(secErr.Errors) > 0 {
		ve.Message = secErr.Errors[0].Error()
	} else {
		ve.Message = secErr.Error()
	}

	for _, err := range secErr.Errors {
		if strings.Contains(err.Error(), "authorization header") {
			ve.Field = "Authorization"
			ve.Expected = "valid authorization header"
			break
		} else if strings.Contains(err.Error(), "apiKey") || strings.Contains(err.Error(), "api key") {
			ve.Field = "API Key"
			ve.Expected = "valid API key"
			break
		}
	}

	rv.logger.WithFields(log.Fields{
		"reason":  ve.Reason,
		"field":   ve.Field,
		"message": ve.Message,
	}).Debug("security validation error")

	return ve
}

func getSchemaTypeInfo(schema *openapi3.SchemaRef) string {
	if schema == nil || schema.Value == nil {
		return "unknown"
	}

	s := schema.Value
	parts := []string{}

	if s.Type != nil && len(*s.Type) > 0 {
		parts = append(parts, "type: "+(*s.Type)[0])
	}
	if s.Format != "" {
		parts = append(parts, "format: "+s.Format)
	}
	if s.Pattern != "" {
		parts = append(parts, "pattern: "+s.Pattern)
	}
	if s.Min != nil {
		parts = append(parts, fmt.Sprintf("min: %v", *s.Min))
	}
	if s.Max != nil {
		parts = append(parts, fmt.Sprintf("max: %v", *s.Max))
	}
	if len(s.Enum) > 0 {
		parts = append(parts, fmt.Sprintf("enum: %v", s.Enum))
	}

	if len(parts) == 0 {
		return "any"
	}
	return strings.Join(parts, ", ")
}

func extractFieldFromSchemaError(err error) string {
	var schemaErr *openapi3.SchemaError
	if errors.As(err, &schemaErr) {
		pointer := schemaErr.JSONPointer()
		if len(pointer) > 0 {
			return pointer[len(pointer)-1]
		}
	}
	return ""
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
