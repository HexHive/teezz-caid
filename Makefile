IMAGE = teezz-caid
DOCKER := docker

DEVICE_ID ?= AAAAAAAAAAAAAAAA
LIB_PATH ?= /system/lib64/libteec.so 


.PHONY: build run


help: ## Show this help
	@egrep -h '\s##\s' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: Dockerfile compose.yaml ## Build the Docker container(s)
	@$(DOCKER) compose build

run: ## Run the Docker container using entrypoint
	@$(DOCKER) compose run --rm \
	  $(IMAGE) /docker-entrypoint.sh $(DEVICE_ID) $(LIB_PATH)
