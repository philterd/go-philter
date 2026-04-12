.PHONY: all build test docker-build clean run

BINARY_NAME=go-philter
DOCKER_IMAGE_NAME=go-philter
VERSION=0.1.0

all: build test

build:
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY_NAME) .

test:
	go test -v ./...

run: build
	./$(BINARY_NAME)

docker-build:
	docker build --build-arg VERSION=$(VERSION) -t $(DOCKER_IMAGE_NAME):$(VERSION) -t $(DOCKER_IMAGE_NAME):latest .

clean:
	rm -f $(BINARY_NAME)
