install:
	go install -v ${LDFLAGS}

deps:
	go get github.com/stretchr/testify

test:
	@go test -v -cover ./...

cover:
	@go test -coverprofile cover.out
