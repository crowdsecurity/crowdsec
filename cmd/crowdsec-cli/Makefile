# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME=cscli
PREFIX?="/"
BIN_PREFIX = $(PREFIX)"/usr/local/bin/"

export LD_OPTS=-ldflags "-s -w -X github.com/crowdsecurity/crowdsec/pkg/cwversion.Version=$(BUILD_VERSION) \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.BuildDate=$(BUILD_TIMESTAMP) \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.Codename=$(BUILD_CODENAME)  \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.Tag=$(BUILD_TAG) \
-X github.com/crowdsecurity/crowdsec/pkg/cwversion.GoVersion=$(BUILD_GOVERSION) \
-extldflags '-static'"

all: clean build

build: clean
	@$(GOBUILD) $(LD_OPTS) -o $(BINARY_NAME) -v

static: clean
	@$(GOBUILD) $(LD_OPTS) -o $(BINARY_NAME) -v -a -tags netgo

install: install-conf install-bin

install-conf:

install-bin:
	@install -v -m 755 -D "$(BINARY_NAME)" "$(BIN_PREFIX)/$(BINARY_NAME)" || exit

uninstall:
	@rm -rf $(CSCLI_CONFIG)
	@rm -rf $(BIN_PREFIX)$(BINARY_NAME)

clean:
	@rm -f $(BINARY_NAME)
