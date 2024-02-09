.PHONY: help
help:
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	| sed -n 's/^.*:\(.*\): \(.*\)##\(.*\)/\1:\3/p' \
	| awk 'BEGIN {FS = ":"; printf "\033[33m"} {printf "%-20s \033[32m %s\033[0m\n", $$1, $$2}'
