check: lint scan test

scan: 
    trivy fs . --dependency-tree

lint: 
	golangci-lint run ./...

changelog:
    git cliff -o CHANGELOG.md

test:
	go test -v  ./...
