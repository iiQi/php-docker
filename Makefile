VERSION := $(if $(VERSION),$(VERSION),"7.3.25")
TYPE := $(if $(TYPE),$(TYPE),"fpm")
EXT := $(if $(EXT),$(EXT),"gm")

all: build push

# Example:
#   make build
#   VERSION=7.3.24 TYPE=fpm make build
.PHONY: build
build:
	docker build --build-arg PHP_VER=$(VERSION)-$(TYPE) -t iiqi/php:$(VERSION)-$(TYPE) -f Dockerfile .

build-ext:
	docker build --build-arg PHP_VER=$(VERSION)-$(TYPE) -t iiqi/php:$(VERSION)-$(TYPE)-$(EXT) -f Dockerfile-$(EXT) .


# Example:
#   make push
#   VERSION=7.3.24 TYPE=fpm make push
.PHONY: push
push:
	docker push iiqi/php:$(VERSION)-$(TYPE)
