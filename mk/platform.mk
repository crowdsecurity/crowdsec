
BUILD_CODENAME ?= alphaga
GOARCH ?= $(shell go env GOARCH)
BUILD_TAG ?= $(shell git rev-parse --short HEAD)

ifeq ($(OS), Windows_NT)
	SHELL := pwsh.exe
	.SHELLFLAGS := -NoProfile -Command
	SYSTEM = windows
	EXT = .exe
else
	SYSTEM ?= $(shell uname -s | tr '[A-Z]' '[a-z]')
	include mk/platform/unix_common.mk
endif

ifneq ("$(wildcard mk/platform/$(SYSTEM).mk)", "")
	include mk/platform/$(SYSTEM).mk
else
	include mk/platform/linux.mk
endif
