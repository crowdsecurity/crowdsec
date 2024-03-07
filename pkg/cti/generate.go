package cti

// To update openapi.yaml:
// curl https://crowdsecurity.github.io/cti-api/v2/swagger.yaml > ./pkg/cti/openapi.yaml

//go:generate go run -mod=mod github.com/deepmap/oapi-codegen/v2/cmd/oapi-codegen@v2.1.0 -package=cti -generate client -o ./client.go ./openapi.yaml
//go:generate go run -mod=mod github.com/deepmap/oapi-codegen/v2/cmd/oapi-codegen@v2.1.0 -package=cti -generate types -o ./types.go ./openapi.yaml

