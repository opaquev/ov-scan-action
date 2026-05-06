.PHONY: build run test clean

BINARY ?= app

build:
	go build -o $(BINARY) ./...

run: build
	./$(BINARY)

test:
	go test ./...

clean:
	rm -f $(BINARY)
