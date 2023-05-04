package main

import (
	"log"
	"net"
	"path"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	flag "github.com/spf13/pflag"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-strip -cflags "$BPF_CFLAGS" -cc clang bpf ./xdp_rrl_per_ip.c -- -I./headers

const (
	bpfFSPath = "/sys/fs/bpf"
)

type Flags struct {
	Interface string
	Threshold uint16
}

type Cfg struct {
	Threshold uint16
}

func (f *Flags) SetFlags() {
	flag.Uint16Var(&f.Threshold, "threshold", 10, "DNS response rate limit per IP")
	flag.StringVar(&f.Interface, "interface", "", "Interface to attach")
}

func GetConfig(flags *Flags) Cfg {
	cfg := Cfg{}
	if flags.Threshold > 0 {
		cfg.Threshold = flags.Threshold
	}
	return cfg
}

func main() {
	flags := Flags{}
	flags.SetFlags()
	flag.Parse()

	if flags.Interface == "" {
		log.Fatalf("Please specify a network interface")
	}
	// Look up the network interface by name.
	ifaceName := flags.Interface
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	xdpDNSRRL := "xdp-dnsrrl"
	pinPath := path.Join(bpfFSPath, xdpDNSRRL)

	var opts ebpf.CollectionOptions
	var bpfSpec *ebpf.CollectionSpec
	objs := &bpfObjects{}

	bpfSpec, err = loadBpf()
	if err != nil {
		log.Fatalf("Failed to load bpf spec: %v", err)
	}

	if err := bpfSpec.RewriteConstants(map[string]interface{}{
		"CFG": GetConfig(&flags),
	}); err != nil {
		log.Fatalf("Failed to rewrite config: %v", err)
	}

	if err := bpfSpec.LoadAndAssign(objs, &opts); err != nil {
		log.Fatalf("Failed to load objects: %v", err)
	}
	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpRrlPerIp,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	err = l.Pin(pinPath)
	if err != nil {
		log.Fatalf("could not pin XDP program: %s", err)
	}
	//	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)

}
