package main

import (
	"flag"
	"log"
	"strings"

	"github.com/Lylelee/jail"
)

func main() {

	pid := flag.Int("pid", -1, "program's pid")

	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if *pid != -1 {
		jail.TrapPID()
		//
	} else if *pid == -1 && len(flag.Args()) > 0 {
		jail.TrapCommandLine(strings.Join(flag.Args(), " "))
	} else if *pid == -1 && len(flag.Args()) == 0 {
		//do nothing
	} else {
		//do nothing
	}
}

// add route https://github.com/teddyking/netsetgo/blob/0.0.1/configurer/container.go#L47-L53
// add ip https://github.com/teddyking/netsetgo/blob/0.0.1/configurer/container.go#L37
// write pcap file https://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket#write-pcap-file
// namespace basic https://medium.com/@teddyking/namespaces-in-go-network-fdcf63e76100
// golang context timeout https://medium.com/@vCabbage/go-timeout-commands-with-os-exec-commandcontext-ba0c861ed738
