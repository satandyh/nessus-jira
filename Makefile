GOPATH=$(shell go env GOPATH)
LINTER_CMD=${GOPATH}/bin/golangci-lint
BINARY_NAME=nessus-jira

.PHONY: all
all: clean fmt lint vet test build

.PHONY: build
build:
	@CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build -o ${BINARY_NAME} -a -ldflags="-w -s" -gcflags=all="-l -B" 
#	CGO_ENABLED=0 GOARCH=amd64 GOOS=darwin go build -o ${BINARY_NAME}-darwin -a

.PHONY: run
run:
	./${BINARY_NAME}

.PHONY: clean
clean:
	@go clean
	@rm -f ${BINARY_NAME}
#	rm ${BINARY_NAME}-darwin

.PHONY: lint
lint: ## lint your code!
	@${LINTER_CMD} run

.PHONY: vet
vet: ## check for suspicious constructions
	@go vet

.PHONY: fmt
fmt: ## do format
	@gofmt -d -s .

.PHONY: test
test:
	@echo "No any test. Play as you want."
