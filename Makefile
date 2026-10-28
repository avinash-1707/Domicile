GOARCH_LINUX ?= $(shell go env GOARCH)

.PHONY: test vet bench-transport

test:
	go test -race ./...

vet:
	go vet ./...

# Measures tunnel transports under shaped loopback (tools/transportbench). Needs
# Docker; runs a privileged throwaway container because tc netem changes
# the container's network.
bench-transport:
	GOOS=linux GOARCH=$(GOARCH_LINUX) CGO_ENABLED=0 go build -o bin/transportbench ./tools/transportbench
	docker run --rm --privileged \
		-v $(CURDIR)/bin:/bench:ro \
		-v $(CURDIR)/tools/transportbench/run.sh:/run.sh:ro \
		alpine sh /run.sh
