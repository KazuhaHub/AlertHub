# AlertHub — single-binary local dev. No Docker, no external broker needed:
# the Go server embeds the MQTT broker (mochi-mqtt) and the React admin SPA.

.PHONY: run build test test-go test-pg tidy clean help web-build web-dev web-install ci fmt-check

help:
	@echo "make run        - start broker + API + web UI + /admin (one command)"
	@echo "make web-build  - build the React admin SPA into the Go embed dir"
	@echo "make web-dev    - run the admin SPA with Vite HMR (proxies API to :8080)"
	@echo "make build      - web-build + go build ./bin/alerthub"
	@echo "make test       - cross-language signing conformance"
	@echo "make test-go    - go unit tests (sqlite path)"
	@echo "make test-pg    - go store + RLS integration tests (needs ALERTHUB_TEST_PG_DSN)"
	@echo "make ci         - the full CI gate locally (fmt + vet + build + test + conformance)"
	@echo "make clean      - remove db + binary"

# Mirrors .github/workflows/ci.yml so you can reproduce the gate before pushing.
# Set ALERTHUB_TEST_PG_DSN to also exercise the Postgres/RLS tests.
ci: fmt-check
	go vet ./server/...
	go build ./server/...
	go test -count=1 ./server/...
	./scripts/conformance.sh

fmt-check:
	@unformatted="$$(gofmt -l server/)"; \
	if [ -n "$$unformatted" ]; then \
		echo "not gofmt-clean:"; echo "$$unformatted"; exit 1; \
	fi

run:
	go run ./server

web-install:
	cd web-admin && npm install

web-build:
	cd web-admin && npx vite build

web-dev:
	cd web-admin && npm run dev

# Stamp build identity so `/readyz`, the startup log line and the
# alerthub_build_info metric can answer "what are you running?".
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
LDFLAGS := -X github.com/KazuhaHub/AlertHub/server/internal/obs.version=$(VERSION) \
           -X github.com/KazuhaHub/AlertHub/server/internal/obs.commit=$(COMMIT)

build: web-build
	go build -ldflags "$(LDFLAGS)" -o bin/alerthub ./server

test:
	./scripts/conformance.sh

test-go:
	go test ./server/...

# Set ALERTHUB_TEST_PG_DSN to a disposable database, e.g.
#   ALERTHUB_TEST_PG_DSN="postgres://$$USER@localhost:5432/alerthub_test?sslmode=disable" make test-pg
test-pg:
	go test ./server/internal/store/... -run TestPostgres -v

tidy:
	go mod tidy

clean:
	rm -f alerthub.db alerthub.db-shm alerthub.db-wal
	rm -rf bin
