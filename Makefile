.PHONY: install uninstall test list count

SHELL := /bin/bash

install:
	@bash install.sh

uninstall:
	@bash install.sh --uninstall

list:
	@bash clawhub-lint.sh list

count:
	@bash clawhub-lint.sh count

test:
	@echo "Running tests..."
	@if [ -d tests ] && ls tests/*.sh 1>/dev/null 2>&1; then \
		for t in tests/*.sh; do \
			echo "  $$t"; \
			bash "$$t" || exit 1; \
		done; \
		echo "All tests passed."; \
	else \
		echo "No test files found in tests/"; \
	fi
