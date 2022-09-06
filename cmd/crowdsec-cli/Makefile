ifeq ($(OS),Windows_NT)
SHELL := pwsh.exe
.SHELLFLAGS := -NoProfile -Command
EXT=.exe
endif


# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME=cscli$(EXT)
# names longer than 15 chars break 'pgrep'
BINARY_NAME_COVER=$(BINARY_NAME).cover
PREFIX?="/"
BIN_PREFIX = $(PREFIX)"/usr/local/bin/"

.PHONY: all
all: clean build

build: clean
	@$(GOBUILD) $(LD_OPTS) -o $(BINARY_NAME)

build-bincover: clean
	$(GOTEST) . -tags testrunmain -coverpkg=$(go list github.com/crowdsecurity/crowdsec/... | grep -v -e 'pkg/database' -e 'plugins/notifications' -e 'pkg/protobufs' -e 'pkg/cwversions' -e 'pkg/cstest' -e 'pkg/models') -covermode=atomic $(LD_OPTS) -c -o $(BINARY_NAME_COVER)

build-bincover_static: clean
	$(GOTEST) . -tags testrunmain -coverpkg=$(go list github.com/crowdsecurity/crowdsec/... | grep -v -e 'pkg/database' -e 'plugins/notifications' -e 'pkg/protobufs' -e 'pkg/cwversions' -e 'pkg/cstest' -e 'pkg/models') -covermode=atomic $(LD_OPTS_STATIC) -c -o $(BINARY_NAME_COVER)


static: clean
	@$(GOBUILD) $(LD_OPTS_STATIC) -o $(BINARY_NAME) -a

.PHONY: install
install: install-conf install-bin

install-conf:

install-bin:
	@install -v -m 755 -D "$(BINARY_NAME)" "$(BIN_PREFIX)/$(BINARY_NAME)" || exit

uninstall:
	@$(RM) $(CSCLI_CONFIG) $(WIN_IGNORE_ERR)
	@$(RM) $(BIN_PREFIX)$(BINARY_NAME) $(WIN_IGNORE_ERR)

clean:
	@$(RM) $(BINARY_NAME) $(BINARY_NAME_COVER) $(WIN_IGNORE_ERR)
