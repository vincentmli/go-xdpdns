package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "$BPF_CFLAGS" -cc clang bpf ./xdp_rrl_per_ip.c -- -I./headers

const (
	bpfFSPath = "/sys/fs/bpf"
)

func startTicker(f func()) chan bool {
	done := make(chan bool, 1)
	go func() {
		ticker := time.NewTicker(time.Second * 1)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				f()
			case <-done:
				fmt.Println("done")
				return
			}
		}
	}()
	return done
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	xdpDNSRRL := "xdp-dnsrrl"
	pinPath := path.Join(bpfFSPath, xdpDNSRRL)
	/*
	   if err := os.MkdirAll(pinPath, os.ModePerm); err != nil {
	           log.Fatalf("failed to create bpf fs subpath: %+v", err)
	   }
	*/

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, &ebpf.CollectionOptions{}); err != nil {
		log.Fatalf("loading objects: %s", err)
	}

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
	/*
		log.Printf("Press Ctrl-C to exit and remove the program")

		done := startTicker(func() {
			fmt.Println("tick...")
		})
		time.Sleep(120 * time.Second)
		close(done)
		time.Sleep(5 * time.Second)
	*/

}
