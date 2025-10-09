.DEFAULT_GOAL := help

# default value if not provided
VERBOSE ?= 0
IMAGE ?= *
PRUNE ?= $(if $(filter *,$(IMAGE)),1,0)

.PHONY: help
help: ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*##"; printf "\033[36m\033[0m"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)


check_for_hadolint:
	@echo "Checking if hadolint is available..."
	@if ! command -v hadolint >/dev/null 2>&1; then \
		echo >&2 "Error: hadolint is not installed or not in PATH. Install hadolint (https://github.com/hadolint/hadolint)"; \
		exit 1; \
	else \
	  echo "hadolint version $$(hadolint --version | grep -oP 'v\d+\.\d+\.\d+')"; \
	fi;

check_for_docker:
	@echo "Checking if docker is available..."
	@if ! command -v docker >/dev/null 2>&1; then \
		echo >&2 "Error: docker is not installed or not in PATH. Install Docker (https://docs.docker.com/get-docker/)"; \
		exit 1; \
	else \
	  echo "Docker version $$(docker --version | awk '{print $$3}' | sed 's/,//')"; \
	fi;

check_image:
	@if [ "$(IMAGE)" != "*" ] && [ ! -d "$(IMAGE)" ]; then \
		echo >&2 "Error: Image directory '$(IMAGE)' not found"; \
		exit 1; \
	fi

##@ Linting

lint: check_for_hadolint check_image ## Run hadolint on all Dockerfiles or a specific image using IMAGE=name
	@echo "Running hadolint on Dockerfiles..."
	@for dockerfile in $(IMAGE)/Dockerfile*; do \
		if [ -f "$$dockerfile" ]; then \
			echo "Linting $$dockerfile"; \
			if [ "$(VERBOSE)" = "1" ]; then \
				hadolint "$$dockerfile"; \
			else \
				hadolint "$$dockerfile" || true; \
			fi; \
		fi; \
	done

##@ Building

build_amd64: check_for_docker check_image ## Build Docker image(s) for AMD64 architecture. Use IMAGE=name
	@echo "Building Docker images for linux/amd64..."
	@for dir in $(IMAGE)/; do \
		if [ -d "$$dir" ]; then \
			image_name=$$(basename "$$dir"); \
			for dockerfile in $$dir/Dockerfile*; do \
				if [ -f "$$dockerfile" ]; then \
					version=$$(echo "$$dockerfile" | sed 's/.*Dockerfile_//'); \
					if [ "$$version" = "$$dockerfile" ]; then \
						version="latest"; \
					fi; \
					echo "Building $$image_name:$$version (amd64) from $$dockerfile"; \
					docker build \
						--platform linux/amd64 \
						-t getwilds/$$image_name:$$version-amd64 \
						-f "$$dockerfile" \
						"$$dir"; \
					if [ "$(PRUNE)" = "1" ]; then \
						echo "Cleaning up Docker build cache..."; \
						docker system prune -f; \
					fi; \
				fi; \
			done; \
		fi; \
	done

build_arm64: check_for_docker check_image ## Build Docker image(s) for ARM64 architecture. Use IMAGE=name
	@echo "Building Docker images for linux/arm64..."
	@for dir in $(IMAGE)/; do \
		if [ -d "$$dir" ]; then \
			image_name=$$(basename "$$dir"); \
			for dockerfile in $$dir/Dockerfile*; do \
				if [ -f "$$dockerfile" ]; then \
					version=$$(echo "$$dockerfile" | sed 's/.*Dockerfile_//'); \
					if [ "$$version" = "$$dockerfile" ]; then \
						version="latest"; \
					fi; \
					echo "Building $$image_name:$$version (arm64) from $$dockerfile"; \
					docker build \
						--platform linux/arm64 \
						-t getwilds/$$image_name:$$version-arm64 \
						-f "$$dockerfile" \
						"$$dir"; \
					if [ "$(PRUNE)" = "1" ]; then \
						echo "Cleaning up Docker build cache..."; \
						docker system prune -f; \
					fi; \
				fi; \
			done; \
		fi; \
	done

build: build_amd64 build_arm64 ## Build Docker image(s) for both AMD64 and ARM64 architectures. Use IMAGE=name for specific image, or leave blank for all

##@ Testing

test: lint build ## Run full test suite: lint and build for both architectures. Use IMAGE=name for specific image, or leave blank for all
