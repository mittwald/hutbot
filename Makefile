PYTHON ?= python3
PIP ?= $(PYTHON) -m pip
DOCKER ?= docker
HELM ?= helm

IMAGE_REPOSITORY ?= ghcr.io/mittwald/hutbot

# An image is published per pushed tag, so the newest tag is the newest deployable image and
# the default for a deploy. Sorted by creation date, not by version: git's version sort ranks
# a prerelease (v1.1.0-alpha.36) against its release (v1.1.0) in a way nobody wants to reason
# about, and "latest" here means "the one cut most recently". Override with IMAGE_TAG=v1.2.3.
LATEST_TAG = $(shell git tag -l 'v[0-9]*' --sort=-creatordate 2>/dev/null | head -n 1)
IMAGE_TAG ?= $(LATEST_TAG)

# What `make image` labels a local build: a tag plus the commits and dirt on top of it, which
# is exactly what must NOT be deployed — hence a separate variable from IMAGE_TAG.
BUILD_TAG ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE := $(IMAGE_REPOSITORY):$(BUILD_TAG)
ARGS ?=

.DEFAULT_GOAL := help

.PHONY: help install run check python-check shellcheck helm-lint test test-deployment \
	image push seed-vault seed-vault-dev sync-secret sync-secret-dev calendars calendars-dev \
	tags require-image-tag deploy-dev deploy-prod

help: ## Show available targets
	@echo "Hutbot targets:"
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[1m%-16s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "vars: IMAGE_REPOSITORY, IMAGE_TAG (default: $(if $(LATEST_TAG),$(LATEST_TAG),none found)), BUILD_TAG, ARGS"

install: ## Install runtime and development dependencies
	$(PIP) install -r requirements-dev.txt

run: ## Run the bot from source
	$(PYTHON) -m hutbot

check: python-check shellcheck helm-lint test ## Run every static check and the test suite

python-check: ## Compile-check the Python sources
	$(PYTHON) -m compileall -q hutbot bot.py employee_list.py webui.py

shellcheck: ## Check the deployment scripts
	shellcheck deploy-dev.sh deploy-prod.sh scripts/sync-secret.sh scripts/edit-calendars.sh \
		scripts/seed-vault.sh

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

seed-vault: ## Seed the production Vault path from .env, once [ARGS='--dry-run']
	./scripts/seed-vault.sh --env prod $(ARGS)

seed-vault-dev: ## Seed the dev Vault path from .env-dev, once [ARGS='--dry-run']
	./scripts/seed-vault.sh --env dev $(ARGS)

sync-secret: ## Sync the production Secret from Vault [ARGS='--restart']
	./scripts/sync-secret.sh --env prod $(ARGS)

sync-secret-dev: ## Sync the dev Secret from Vault [ARGS='--restart']
	./scripts/sync-secret.sh --env dev $(ARGS)

calendars: ## Edit the production built-in calendar list in Vault [ARGS='--sync']
	./scripts/edit-calendars.sh --env prod $(ARGS)

calendars-dev: ## Edit the dev built-in calendar list in Vault [ARGS='--sync']
	./scripts/edit-calendars.sh --env dev $(ARGS)

tags: ## Show the most recent release tags
	@git tag -l 'v[0-9]*' --sort=-creatordate | head -n 5

require-image-tag:
	@test -n "$(IMAGE_TAG)" || { \
		echo "error: no v* git tag found and no IMAGE_TAG given" >&2; \
		echo "       run \`git fetch --tags\`, or pass IMAGE_TAG=v1.2.3" >&2; \
		exit 1; }
	@git rev-parse -q --verify "refs/tags/$(IMAGE_TAG)" >/dev/null \
		|| echo "warning: $(IMAGE_TAG) is not a tag in this clone — make sure that image exists" >&2
	@ahead=$$(git rev-list --count "$(IMAGE_TAG)..HEAD" 2>/dev/null || echo 0); \
		test "$$ahead" = 0 \
		|| echo "warning: HEAD is $$ahead commit(s) ahead of $(IMAGE_TAG); that image has none of them" >&2

deploy-dev: require-image-tag ## Deploy dev with the newest tag [IMAGE_TAG=v1.2.3] [ARGS='diff']
	./deploy-dev.sh "$(IMAGE_TAG)" $(ARGS)

deploy-prod: require-image-tag ## Deploy production with the newest tag [IMAGE_TAG=v1.2.3] [ARGS='diff']
	./deploy-prod.sh "$(IMAGE_TAG)" $(ARGS)
