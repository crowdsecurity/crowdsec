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
	log "github.com/sirupsen/logrus"
)

var (
	ErrInvalidSchemaName = errors.New("invalid schema name")
)

// RoutePolicy controls what the validator does when the router cannot match a
// request against the loaded schema (either because the path is unknown or
// because no method of the matched path accepts the request).
type RoutePolicy string

const (
	// RoutePolicyDrop treats an unmatched route as a validation failure.
	RoutePolicyDrop RoutePolicy = "drop"
	// RoutePolicyIgnore lets the request through without validation when the
	// router cannot match it.
	RoutePolicyIgnore RoutePolicy = "ignore"
)

func (p RoutePolicy) validate() error {
	switch p {
	case RoutePolicyDrop, RoutePolicyIgnore:
		return nil
	}
	return fmt.Errorf("invalid route policy %q (expected %q or %q)", p, RoutePolicyDrop, RoutePolicyIgnore)
}

// SchemaOptions configures per-schema validation behavior. A nil *SchemaOptions
// passed to LoadSchema means "use defaults" (both policies = drop, matching
// pre-option behavior).
type SchemaOptions struct {
	OnRouteNotFound    RoutePolicy
	OnMethodNotAllowed RoutePolicy
}

func (o *SchemaOptions) withDefaults() SchemaOptions {
	out := SchemaOptions{
		OnRouteNotFound:    RoutePolicyDrop,
		OnMethodNotAllowed: RoutePolicyDrop,
	}
	if o == nil {
		return out
	}
	if o.OnRouteNotFound != "" {
		out.OnRouteNotFound = o.OnRouteNotFound
	}
	if o.OnMethodNotAllowed != "" {
		out.OnMethodNotAllowed = o.OnMethodNotAllowed
	}
	return out
}

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
	Schema  *openapi3.T
	Router  routers.Router
	Options SchemaOptions
}

// builtinBodyDecoders is the set of decoder identifiers we expose to users.
// The names are intentionally stable (decoupled from kin-openapi's internal
// symbol names), so the underlying library can rename/reshape its API without
// forcing a user-visible config change. "zip" is deliberately excluded: the
// kin-openapi zip decoder has no zip-bomb protection.
var builtinBodyDecoders = map[string]openapi3filter.BodyDecoder{
	"json":       openapi3filter.JSONBodyDecoder,
	"urlencoded": openapi3filter.UrlencodedBodyDecoder,
	"multipart":  openapi3filter.MultipartBodyDecoder,
	"yaml":       openapi3filter.YamlBodyDecoder,
	"csv":        openapi3filter.CsvBodyDecoder,
	"plain":      openapi3filter.PlainBodyDecoder,
	"file":       openapi3filter.FileBodyDecoder,
}

// kinDefaultContentTypes enumerates the content types kin-openapi pre-registers
// in its package init. We drop all of them so we control exactly which body
// decoders are reachable.
var kinDefaultContentTypes = []string{
	"application/json",
	"application/json-patch+json",
	"application/merge-patch+json",
	"application/ld+json",
	"application/hal+json",
	"application/vnd.api+json",
	"application/octet-stream",
	"application/problem+json",
	"application/x-www-form-urlencoded",
	"application/x-yaml",
	"application/yaml",
	"application/zip",
	"multipart/form-data",
	"text/csv",
	"text/plain",
}

// allowedDefaultContentTypes is the set we register by default in
// NewRequestValidator. Anything else (yaml, plain text, csv, file uploads of
// raw binary…) has to be opted into by the user via RegisterBodyDecoder.
var allowedDefaultContentTypes = map[string]openapi3filter.BodyDecoder{
	"application/json":                  openapi3filter.JSONBodyDecoder,
	"application/json-patch+json":       openapi3filter.JSONBodyDecoder,
	"application/merge-patch+json":      openapi3filter.JSONBodyDecoder,
	"application/ld+json":               openapi3filter.JSONBodyDecoder,
	"application/hal+json":              openapi3filter.JSONBodyDecoder,
	"application/vnd.api+json":          openapi3filter.JSONBodyDecoder,
	"application/problem+json":          openapi3filter.JSONBodyDecoder,
	"application/x-www-form-urlencoded": openapi3filter.UrlencodedBodyDecoder,
	"multipart/form-data":               openapi3filter.MultipartBodyDecoder,
}

type RequestValidator struct {
	loaders        map[string]*openapi3.Loader
	openAPISchemas map[string]SchemaData
	logger         *log.Entry
}

func NewRequestValidator(logger *log.Entry) *RequestValidator {
	// kin-openapi keeps its body-decoder registry in a package-level global
	// (openapi3filter.bodyDecoders). We cannot scope decoder availability per
	// RequestValidator instance without forking the library. In a process with
	// multiple appsec datasources, the registry is therefore shared — the last
	// validator to reset + register defaults wins. Today this is fine (one
	// appsec datasource per process is the norm). If per-datasource isolation
	// is ever needed, pre-filtering request Content-Type against a per-
	// validator allowlist before calling openapi3filter.ValidateRequest is the
	// cleanest path forward.
	for _, ct := range kinDefaultContentTypes {
		openapi3filter.UnregisterBodyDecoder(ct)
	}
	for ct, decoder := range allowedDefaultContentTypes {
		openapi3filter.RegisterBodyDecoder(ct, decoder)
	}

	return &RequestValidator{
		loaders:        make(map[string]*openapi3.Loader),
		openAPISchemas: make(map[string]SchemaData),
		logger:         logger,
	}
}

// RegisterBodyDecoder registers a decoder for the given Content-Type so that
// a loaded OpenAPI schema can declare and validate requests of that type.
// decoderName must be one of the built-in identifiers: "json", "urlencoded",
// "multipart", "yaml", "csv", "plain", "file". Note that this mutates
// kin-openapi's process-global decoder registry — see the note on
// NewRequestValidator.
func (rv *RequestValidator) RegisterBodyDecoder(contentType, decoderName string) error {
	decoder, ok := builtinBodyDecoders[decoderName]
	if !ok {
		return fmt.Errorf("unknown body decoder %q", decoderName)
	}
	openapi3filter.RegisterBodyDecoder(contentType, decoder)
	rv.logger.Debugf("registered body decoder %q for content type %q", decoderName, contentType)
	return nil
}

// warnUnsupportedSecuritySchemes scans a schema's declared security schemes
// once at load time and warns for types the WAF cannot enforce (oauth2,
// openIdConnect). Any request hitting a route guarded by such a scheme will
// fail validation at runtime; the warning is emitted here so operators learn
// about the gap during schema load rather than via per-request log spam.
func (rv *RequestValidator) warnUnsupportedSecuritySchemes(ref string, doc *openapi3.T) {
	if doc.Components == nil {
		return
	}
	for name, schemeRef := range doc.Components.SecuritySchemes {
		if schemeRef == nil || schemeRef.Value == nil {
			continue
		}
		switch schemeRef.Value.Type {
		case "oauth2", "openIdConnect":
			rv.logger.Warnf("schema %q: security scheme %q (type %s) is not supported and will fail validation for any request that requires it",
				ref, name, schemeRef.Value.Type)
		}
	}
}

func (_ *RequestValidator) authFunc(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
	authTokenValue := ""
	switch input.SecurityScheme.Type {
	case "http":
		switch input.SecurityScheme.Scheme {
		case "basic":
			values := input.RequestValidationInput.Request.Header["Authorization"]
			if len(values) == 0 {
				return errors.New("authorization header not found")
			}
			if len(values) > 1 {
				return errors.New("multiple Authorization headers found")
			}
			if !strings.HasPrefix(values[0], "Basic ") {
				return errors.New("authorization header does not start with 'Basic '")
			}
			authTokenValue = values[0][6:]
		case "bearer":
			values := input.RequestValidationInput.Request.Header["Authorization"]
			if len(values) == 0 {
				return errors.New("authorization header not found")
			}
			if len(values) > 1 {
				return errors.New("multiple Authorization headers found")
			}
			if !strings.HasPrefix(values[0], "Bearer ") {
				return errors.New("authorization header does not start with 'Bearer '")
			}
			authTokenValue = values[0][7:]
		}
	case "apiKey":
		switch input.SecurityScheme.In {
		case "query":
			//Because we are checking for the presence of the API key, it probably does not matter if go drops parameters using ; as a separator
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
	case "oauth2", "openIdConnect":
		// Warned at schema load (see warnUnsupportedSecuritySchemes); fail
		// the auth check here since we cannot validate these from the WAF.
		return fmt.Errorf("%s security scheme not supported", input.SecurityScheme.Type)
	default:
		return fmt.Errorf("unsupported security scheme type %s", input.SecurityScheme.Type)
	}
	if authTokenValue == "" {
		return errors.New("auth token is required but not provided")
	}

	return nil
}

func (rv *RequestValidator) LoadSchema(ref string, schema string, opts *SchemaOptions) error {
	if ref == "" {
		return errors.New("ref cannot be empty")
	}
	rv.logger.Debugf("loading schema for ref %s", ref)

	if _, exists := rv.loaders[ref]; exists {
		return fmt.Errorf("attempting to load a new schema for existing ref %s", ref)
	}

	options := opts.withDefaults()
	if err := options.OnRouteNotFound.validate(); err != nil {
		return fmt.Errorf("on_route_not_found: %w", err)
	}
	if err := options.OnMethodNotAllowed.validate(); err != nil {
		return fmt.Errorf("on_method_not_allowed: %w", err)
	}

	loader := openapi3.NewLoader()
	rv.loaders[ref] = loader

	doc, err := loader.LoadFromData([]byte(schema))
	if err != nil {
		return fmt.Errorf("failed to load schema %s: %w", ref, err)
	}

	// Is it a valid OpenAPI schema?
	// TODO: look into opts, should we expose some of them to the user ?
	if err := doc.Validate(loader.Context, openapi3.DisableExamplesValidation()); err != nil {
		return fmt.Errorf("failed to validate schema %s: %w", ref, err)
	}

	rv.warnUnsupportedSecuritySchemes(ref, doc)

	router, err := legacyrouter.NewRouter(doc)
	if err != nil {
		return fmt.Errorf("failed to create router for schema ref %s: %w", ref, err)
	}

	rv.openAPISchemas[ref] = SchemaData{
		Schema:  doc,
		Router:  router,
		Options: options,
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
		// The legacy router returns a fresh *routers.RouteError rather than the
		// exported sentinels, so we branch on Reason instead of errors.Is.
		var routeErr *routers.RouteError
		if errors.As(err, &routeErr) {
			switch routeErr.Reason {
			case routers.ErrPathNotFound.Error():
				if schemaData.Options.OnRouteNotFound == RoutePolicyIgnore {
					rv.logger.Debugf("no matching route for %s %s, ignoring per schema policy", r.Method, r.URL.Path)
					return nil
				}
				return &ValidationError{
					Reason:        "route_not_found",
					Message:       routeErr.Reason,
					OriginalError: err,
				}
			case routers.ErrMethodNotAllowed.Error():
				if schemaData.Options.OnMethodNotAllowed == RoutePolicyIgnore {
					rv.logger.Debugf("method %s not allowed for %s, ignoring per schema policy", r.Method, r.URL.Path)
					return nil
				}
				return &ValidationError{
					Reason:        "method_not_allowed",
					Message:       routeErr.Reason,
					OriginalError: err,
				}
			}
		}
		return fmt.Errorf("failed to find route for request: %w (error type: %T)", err, err)
	}

	input := &openapi3filter.RequestValidationInput{
		Request:     r,
		QueryParams: r.URL.Query(),
		Route:       route,
		PathParams:  pathParam,
		Options: &openapi3filter.Options{
			// Stop at the 1st error, we are a WAF, not an actual schema validator
			// And having multiple errors would make it harder to expose a proper event to the user
			MultiError:         false,
			AuthenticationFunc: rv.authFunc,
		},
	}

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
