# Go parameters
GOCMD=go
GORUN=$(GOCMD) run
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOVENDOR=$(GOCMD) mod vendor
MAIN_FILE=main.go

all: test build
build: deps
	$(GOBUILD) -o $(BINARY_NAME) -v
test: 
	$(GOTEST)  ./...
clean: 
	$(GOCLEAN)
run: 
	$(GORUN) $(MAIN_FILE)
deps: 
	$(GOGET) $(GOVENDOR)
