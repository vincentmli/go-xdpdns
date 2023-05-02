GO := go
GO_BUILD = CGO_ENABLED=0 $(GO) build
GO_GENERATE = $(GO) generate
BPF_CFLAGS="-g -Wall"
TARGET=dns-rrl


$(TARGET):
	$(GO_GENERATE)
	$(GO_BUILD) \
                -ldflags "-w -s"

clean:
	rm -f $(TARGET)
	rm -f bpf*
	rm -f go-xdpdns

.PHONY: $(TARGET)
