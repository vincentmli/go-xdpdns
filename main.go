package main

import (
	"bufio"
	"log"
	"net"
	"os"
	"path"
	"strings"

	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	flag "github.com/spf13/pflag"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-strip -cflags "$BPF_CFLAGS" -cc clang bpf ./xdp_rrl.c -- -I./headers
const (
	bpfFSPath = "/sys/fs/bpf"
)

type ExcludeIP4Key4 struct {
	PrefixLen uint32
	ExcludeIP types.IPv4
}

func NewExcludeIP4Key4(excludeIP net.IP, excludeMask net.IPMask) ExcludeIP4Key4 {

	key := ExcludeIP4Key4{}

	ones, _ := excludeMask.Size()
	copy(key.ExcludeIP[:], excludeIP.To4())
	//key.PrefixLen = PolicyStaticPrefixBits + uint32(ones) this is broken to cause invalid argument
	key.PrefixLen = uint32(ones)

	return key
}

type Flags struct {
	Interface string
	Import    string
	Ratelimit uint16
	Numcpus   uint8
}

type Cfg struct {
	Ratelimit uint16
	Numcpus   uint8
}

func (f *Flags) SetFlags() {
	flag.Uint16Var(&f.Ratelimit, "ratelimit", 20, "DNS response rate limit per IP")
	flag.Uint8Var(&f.Numcpus, "numcpus", 2, "DNS response rate limit per IP")
	flag.StringVar(&f.Interface, "interface", "", "Interface to attach")
	flag.StringVar(&f.Import, "import", "", "excluded ipv4 prefix file")
}

func GetConfig(flags *Flags) Cfg {
	cfg := Cfg{}
	if flags.Ratelimit > 0 {
		cfg.Ratelimit = flags.Ratelimit
	}
	if flags.Numcpus > 0 {
		cfg.Numcpus = flags.Numcpus
	}
	return cfg
}

// readLines reads a whole file into memory
// and returns a slice of its lines.
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
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

	xdpProg := "DNSProgRRL"
	xdpProgPath := path.Join(pinPath, xdpProg)

	if err := os.MkdirAll(pinPath, os.ModePerm); err != nil {
		log.Fatalf("failed to create bpf fs subpath: %+v", err)
	}

	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			// Pin the map to the BPF filesystem and configure the
			// library to automatically re-write it in the BPF
			// program so it can be re-used if it already exists or
			// create it if not
			PinPath: pinPath,
		},
	}
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

	var keySlice []ExcludeIP4Key4
	var valueSlice []uint64

	if flags.Import != "" {
		ipv4PrefixFileName := flags.Import
		excludeIPs, err := readLines(ipv4PrefixFileName)
		if err != nil {
			log.Fatalf("readLines: %s", err)
		}
		for _, ip := range excludeIPs {

			if !strings.Contains(ip, "/") {

				ip += "/32"

			}
			//_, ipnet, err := net.ParseCIDR(ip)
			srcIP, ipnet, err := net.ParseCIDR(ip)

			if err != nil {
				log.Printf("malformed ip %v \n", err)
				continue
			}

			// populate key and value slices for BatchUpdate, initilize value to 0
			key4 := NewExcludeIP4Key4(srcIP, ipnet.Mask)
			keySlice = append(keySlice, key4)
			valueSlice = append(valueSlice, uint64(0))
		}

		count, err := objs.ExcludeV4Prefixes.BatchUpdate(keySlice, valueSlice, nil)
		if err != nil {
			log.Fatalf("BatchUpdate: %v", err)
		}
		if count != len(keySlice) {
			log.Fatalf("BatchUpdate: expected count, %d, to be %d", count, len(keySlice))
		}

	}

	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpDnsCookies,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	err = l.Pin(xdpProgPath)
	if err != nil {
		log.Fatalf("could not pin XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)

}
