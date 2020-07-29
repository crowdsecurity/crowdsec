# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME=cscli
PREFIX?="/"
BIN_PREFIX = $(PREFIX)"/usr/local/bin/"

all: clean build

build: clean
	@$(GOBUILD) $(LD_OPTS) -o $(BINARY_NAME) -v

static: clean
	@$(GOBUILD) -o $(BINARY_NAME) -v -a -tags netgo -ldflags '-w -extldflags "-static"'

install: install-conf install-bin

install-conf:

install-bin:
	@install -v -m 755 -D "$(BINARY_NAME)" "$(BIN_PREFIX)/$(BINARY_NAME)" || exit

uninstall:
	@rm -rf $(CSCLI_CONFIG)
	@rm -rf $(BIN_PREFIX)$(BINARY_NAME)

clean:
	@rm -f $(BINARY_NAME)
