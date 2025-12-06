# YARA Operator Makefile

# Image URL to use for building/pushing
IMG ?= yara-operator:latest
API_IMG ?= yara-api:latest

# Get the currently used golang install path
GOBIN ?= $(shell go env GOBIN)
ifeq ($(GOBIN),)
GOBIN = $(shell go env GOPATH)/bin
endif

# Setting SHELL to bash
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

.PHONY: help
help:
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: ## Generate CRD manifests
	@echo "Generating CRD manifests..."
	@mkdir -p config/crd/bases

.PHONY: generate
generate: ## Generate code
	go generate ./...

.PHONY: fmt
fmt: ## Run go fmt
	go fmt ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: test
test: fmt vet ## Run tests
	go test ./... -coverprofile cover.out

##@ Build

.PHONY: build
build: fmt vet ## Build operator binary
	go build -o bin/operator cmd/operator/main.go

.PHONY: build-api
build-api: fmt vet ## Build API server binary
	go build -o bin/api cmd/api/main.go

.PHONY: run
run: fmt vet ## Run operator from host
	go run cmd/operator/main.go

.PHONY: run-api
run-api: fmt vet ## Run API server from host
	go run cmd/api/main.go

##@ Docker

.PHONY: docker-build
docker-build: ## Build docker image for operator
	docker build -t ${IMG} -f Dockerfile.operator .

.PHONY: docker-build-api
docker-build-api: ## Build docker image for API server
	docker build -t ${API_IMG} -f Dockerfile.api .

.PHONY: docker-push
docker-push: ## Push operator docker image
	docker push ${IMG}

.PHONY: docker-push-api
docker-push-api: ## Push API server docker image
	docker push ${API_IMG}

##@ Deployment

.PHONY: install
install: manifests ## Install CRDs into the cluster
	kubectl apply -f config/crd/bases/

.PHONY: uninstall
uninstall: ## Uninstall CRDs from the cluster
	kubectl delete -f config/crd/bases/

.PHONY: deploy
deploy: manifests ## Deploy operator to the cluster
	kubectl apply -f config/rbac/
	kubectl apply -f config/manager/

.PHONY: undeploy
undeploy: ## Undeploy operator from the cluster
	kubectl delete -f config/manager/
	kubectl delete -f config/rbac/

##@ Helm

.PHONY: helm-install
helm-install: ## Install using Helm
	helm install yara-operator ./charts/yara-operator

.PHONY: helm-upgrade
helm-upgrade: ## Upgrade using Helm
	helm upgrade yara-operator ./charts/yara-operator

.PHONY: helm-uninstall
helm-uninstall: ## Uninstall using Helm
	helm uninstall yara-operator

