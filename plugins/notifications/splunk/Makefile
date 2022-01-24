# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME=notification-splunk

build: clean
	@$(GOBUILD) $(LD_OPTS) -o $(BINARY_NAME) -v

clean:
	@$(RM) "$(BINARY_NAME)"

static: clean
	$(GOBUILD) $(LD_OPTS_STATIC) -o $(BINARY_NAME) -v -a -tags netgo
