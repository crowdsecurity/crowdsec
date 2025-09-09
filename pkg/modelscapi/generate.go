package modelscapi

//go:generate env GOTOOLCHAIN=go1.24.6 go run -mod=mod github.com/go-swagger/go-swagger/cmd/swagger@v0.32.3 generate model --spec=./centralapi_swagger.yaml --target=../ --model-package=modelscapi

