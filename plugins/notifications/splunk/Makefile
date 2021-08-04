
# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME=notification-splunk
PREFIX?="/"
BIN_PREFIX = $(PREFIX)"/etc/crowdsec/plugins/"


build: clean
	@$(GOBUILD) $(LD_OPTS) -o $(BINARY_NAME) -v

clean:
	@rm -f $(BINARY_NAME)

static: clean
	$(GOBUILD) $(LD_OPTS_STATIC) -o $(BINARY_NAME) -v -a -tags netgo