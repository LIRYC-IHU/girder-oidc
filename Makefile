COMPOSE := docker compose -f docker-compose.dev.yml
IMAGE := girder-oidc-dev:latest

# The girder/girder base image is published for linux/amd64 only. `docker
# compose build` mis-resolves its single-arch manifest on Apple Silicon, so we
# build the shared image with plain `docker build --platform` (which works) and
# have the compose services reference it by name.

.PHONY: help up down build logs logs-girder logs-dex logs-web shell test clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

build: ## Build the shared dev image (girder + node + plugin, editable)
	docker build --platform linux/amd64 -t $(IMAGE) -f Dockerfile.dev .

up: build ## Build the image and start the dev stack
	$(COMPOSE) up -d

down: ## Stop the dev stack (keeps volumes)
	$(COMPOSE) down

logs: ## Tail all logs
	$(COMPOSE) logs -f

logs-girder: ## Tail girder logs
	$(COMPOSE) logs -f girder

logs-dex: ## Tail dex logs
	$(COMPOSE) logs -f dex

logs-web: ## Tail web client build (vite watch) logs
	$(COMPOSE) logs -f web

shell: ## Open a shell in the girder container
	$(COMPOSE) exec girder bash

test: build ## Run the plugin test suite (pytest-girder) in a container
	$(COMPOSE) run --rm test

clean: ## Stop the stack and remove volumes (DESTROYS data)
	$(COMPOSE) down -v
