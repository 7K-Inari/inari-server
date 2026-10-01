BINARY := bin/inari-server

.PHONY: build test test-integration lint actionlint run migrate docker export-openapi

export-openapi:
	mkdir -p dist
	go run ./cmd/export-openapi dist/openapi.yaml

build:
	go build -o $(BINARY) ./cmd/inari-server

test:
	go test ./...

test-integration:
	go test -tags=integration -count=1 ./...

lint:
	golangci-lint run ./...

actionlint:
	@if command -v actionlint >/dev/null 2>&1; then \
		actionlint .github/workflows/*.y*ml; \
	else \
		docker run --rm -v "$(CURDIR):/repo" --workdir /repo rhysd/actionlint:1.7.12; \
	fi

run:
	go run ./cmd/inari-server

docker:
	docker build -f deploy/docker/Dockerfile -t inari/server:dev .
