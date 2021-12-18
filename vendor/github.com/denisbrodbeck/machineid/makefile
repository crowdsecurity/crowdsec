.PHONY: build clean default test

build: clean
	@go build -o machineid ./cmd/machineid/main.go

clean:
	@rm -rf ./machineid

test:
	go test ./...

default: build
