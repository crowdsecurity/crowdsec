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

type Foo struct {
	Schema *openapi3.T
	Router routers.Router
}

type RequestValidator struct {
	loaders        map[string]*openapi3.Loader
	openAPISchemas map[string]Foo
	logger         *log.Entry
}

func NewRequestValidator(logger *log.Entry) *RequestValidator {
	return &RequestValidator{
		loaders:        make(map[string]*openapi3.Loader),
		openAPISchemas: make(map[string]Foo),
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

	rv.openAPISchemas[ref] = Foo{
		Schema: doc,
		Router: router,
	}

	rv.logger.Infof("loaded schema for ref %s", ref)
	return nil
}

func (rv *RequestValidator) ValidateRequest(ref string, r *http.Request) error {
	ctx := context.TODO()

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
		// This is a validation error
		// We can extract more information from it if needed
		return err
	}
	securityRequirementError := &openapi3filter.SecurityRequirementsError{}
	if errors.As(err, &securityRequirementError) {
		return err
	}
	// Some other error
	rv.logger.Debugf("request validation error: %s (type %T)", err.Error(), err)

	return err
}
