test:
	KAFKA_SKIP_NETTEST=1 \
	KAFKA_VERSION=2.3.1 \
	go test -race -cover ./...

docker:
	docker-compose up -d
