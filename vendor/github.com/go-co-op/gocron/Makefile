.PHONY: fmt check-fmt lint vet test

GO_PKGS   := $(shell go list -f {{.Dir}} ./...)

fmt:
	@go list -f {{.Dir}} ./... | xargs -I{} gofmt -w -s {}

check-fmt:
	@echo "Checking formatting..."
	@FMT="0"; \
	for pkg in $(GO_PKGS); do \
		OUTPUT=`gofmt -l $$pkg/*.go`; \
		if [ -n "$$OUTPUT" ]; then \
			echo "$$OUTPUT"; \
			FMT="1"; \
		fi; \
	done ; \
	if [ "$$FMT" -eq "1" ]; then \
		echo "Problem with formatting in files above."; \
		exit 1; \
	else \
		echo "Success - way to run gofmt!"; \
	fi

lint:
#	Add -set_exit_status=true when/if we want to enforce the linter rules
	@golint -min_confidence 0.8 -set_exit_status $(GO_PKGS)

vet:
	@go vet $(GO_FLAGS) $(GO_PKGS)

test:
	@go test -race -v $(GO_FLAGS) -count=1 $(GO_PKGS)
