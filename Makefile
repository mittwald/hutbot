PYTHON ?= python3
PIP ?= $(PYTHON) -m pip
DOCKER ?= docker
HELM ?= helm

IMAGE_REPOSITORY ?= ghcr.io/mittwald/hutbot
IMAGE_TAG ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE := $(IMAGE_REPOSITORY):$(IMAGE_TAG)
ARGS ?=

.DEFAULT_GOAL := help

.PHONY: help install run check python-check shellcheck helm-lint test test-deployment \
	image push sync-secret sync-secret-dev calendars calendars-dev deploy-dev deploy-prod

help: ## Show available targets
	@echo "Hutbot targets:"
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[1m%-16s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "vars: IMAGE_REPOSITORY, IMAGE_TAG, ARGS"

install: ## Install runtime and development dependencies
	$(PIP) install -r requirements-dev.txt

run: ## Run the bot from source
	$(PYTHON) -m hutbot

check: python-check shellcheck helm-lint test ## Run every static check and the test suite

python-check: ## Compile-check the Python sources
	$(PYTHON) -m compileall -q hutbot bot.py employee_list.py webui.py

shellcheck: ## Check the deployment scripts
	shellcheck deploy-dev.sh deploy-prod.sh scripts/sync-secret.sh scripts/edit-calendars.sh

helm-lint: ## Lint the Helm chart with safe placeholder values
	$(HELM) lint charts/hutbot \
		--set image.tag=check \
		--set existingSecret=hutbot-check

test: ## Run the test suite
	$(PYTHON) -m pytest

test-deployment: ## Run only the chart and deployment-script tests
	$(PYTHON) -m pytest tests/test_deployment_validation.py

image: ## Build the container image
	$(DOCKER) build --tag "$(IMAGE)" .

push: image ## Build and push the container image
	$(DOCKER) push "$(IMAGE)"

sync-secret: ## Sync the production Secret from Vault [ARGS='--restart']
	./scripts/sync-secret.sh --env prod $(ARGS)

sync-secret-dev: ## Sync the dev Secret from Vault [ARGS='--restart']
	./scripts/sync-secret.sh --env dev $(ARGS)

calendars: ## Edit the production built-in calendar list in Vault [ARGS='--sync']
	./scripts/edit-calendars.sh --env prod $(ARGS)

calendars-dev: ## Edit the dev built-in calendar list in Vault [ARGS='--sync']
	./scripts/edit-calendars.sh --env dev $(ARGS)

deploy-dev: ## Deploy dev; pass IMAGE_TAG=v1.2.3 [ARGS='diff']
	./deploy-dev.sh "$(IMAGE_TAG)" $(ARGS)

deploy-prod: ## Deploy production; pass IMAGE_TAG=v1.2.3 [ARGS='diff']
	./deploy-prod.sh "$(IMAGE_TAG)" $(ARGS)
