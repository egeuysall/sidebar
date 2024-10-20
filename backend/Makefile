build:
	@go build -o bin/go

run: build
	@./bin/go

test:
	@go test -v ./...

.PHONY: db dev

db:
	@docker compose -f db/docker-compose.yaml up -d

dev: db
	@trap 'docker compose -f db/docker-compose.yaml stop' INT EXIT; \
	$(MAKE) run