ifeq ($(OS),Windows_NT)
SHELL := powershell.exe
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
PREFIX?="/"
BIN_PREFIX = $(PREFIX)"/usr/local/bin/"

all: clean build

build: clean
	@$(GOBUILD) $(LD_OPTS) -o $(BINARY_NAME) -v

static: clean
	@$(GOBUILD) $(LD_OPTS_STATIC) -o $(BINARY_NAME) -v -a -tags netgo

install: install-conf install-bin

install-conf:

install-bin:
	@install -v -m 755 -D "$(BINARY_NAME)" "$(BIN_PREFIX)/$(BINARY_NAME)" || exit

uninstall:
	@$(RM) $(CSCLI_CONFIG)
	@$(RM) $(BIN_PREFIX)$(BINARY_NAME) $(WIN_IGNORE_ERR)

clean:
	@$(RM) $(BINARY_NAME) $(WIN_IGNORE_ERR)
