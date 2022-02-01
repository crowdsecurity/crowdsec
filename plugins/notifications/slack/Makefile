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
BINARY_NAME=notification-slack$(EXT)

build: clean
	@$(GOBUILD) $(LD_OPTS) -o $(BINARY_NAME) -v

clean:
	@$(RM) $(BINARY_NAME) $(WIN_IGNORE_ERR)


static: clean
	$(GOBUILD) $(LD_OPTS_STATIC) -o $(BINARY_NAME) -v -a -tags netgo
