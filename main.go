package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// NewJailInterface to add correct veth pair names
func NewJailInterface() string {
	allLinks, err := netlink.LinkList()
	if err != nil {
		fmt.Println("get exsit link error")
		fmt.Println(err)
		return ""
	}

	jailIndex := 0

	for _, oneLink := range allLinks {
		linkAttr := oneLink.Attrs()
		if oneLink.Type() == "device" && strings.HasPrefix(linkAttr.Name, "jail") {
			if ji, err := strconv.Atoi(strings.TrimLeft(linkAttr.Name, "jail")); err == nil {
				jailIndex = ji
			}
		}
	}

	if jailIndex > 0 {
		return "jail" + strconv.Itoa(jailIndex+1)
	}

	return "jail0"
}

// CheckSudo to check sudo priviliage
func CheckSudo() {
	cmd := exec.Command("id", "-u")
	output, err := cmd.Output()

	if err != nil {
		log.Fatal(err)
	}

	uid, err := strconv.Atoi(string(output[:len(output)-1]))

	if err != nil {
		log.Fatal(err)
	}

	if uid != 0 {
		log.Fatal("need root to run this program. Creating namespace an veth pair need root privilege")
	}
}

// RemoveLinkExist remove the link if exist
func RemoveLinkExist(vethName string) error {
	vethLink, err := netlink.LinkByName(vethName)
	if err != nil && err.Error() == "Link not found" {
		return nil
	}
	if vethLink == nil {
		return nil
	}
	if err := netlink.LinkSetDown(vethLink); err != nil {
		log.Fatal("cannot set link down veth:", vethName)
	}
	if err := netlink.LinkDel(vethLink); err != nil {
		return err
	}
	return nil
}

func cleanInterfaceNamespace() {
	if err := RemoveLinkExist(hostVethName); err != nil {
		log.Println(err.Error())
	}
	if err := RemoveLinkExist(jailVethName); err != nil {
		log.Println(err.Error())
	}

	if err := netns.DeleteNamed(nsName); err != nil {
		log.Println(err.Error())
		log.Println("deleting a namespace failed:", nsName)
	}
}

func setIPaddress(vethname string, ipcidr string) error {
	link, err := netlink.LinkByName(vethname)
	if err != nil {
		return nil
	}

	ip, ipnet, err := net.ParseCIDR(ipcidr)
	if err != nil {
		return nil
	}
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: ipnet.Mask}}

	if err := netlink.AddrAdd(link, addr); err != nil {
		return err
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	return nil
}

func setupEnviroment() error {
	cmd := exec.Command("bash", "-c", "./iptables_setting.sh")
	output, err := cmd.Output()

	if err != nil {
		log.Println(output)
		return err
	}
	log.Println(string(output))
	return nil
}

func main() {

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	CheckSudo()
	cleanInterfaceNamespace()

	vethLinkAttrs := netlink.NewLinkAttrs()
	vethLinkAttrs.Name = hostVethName

	veth := &netlink.Veth{
		LinkAttrs: vethLinkAttrs,
		PeerName:  jailVethName,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		log.Fatal("fail to add veth pair")
	}

	// configure host jail veth ip
	setIPaddress(hostVethName, "10.8.8.1/24")

	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save the current network namespace
	origns, _ := netns.Get()
	defer origns.Close()

	newns, _ := netns.New()
	defer newns.Close()

	nsPath := filepath.Join("/var/run/netns", nsName)
	f, err := os.Create(nsPath)
	if err != nil {
		log.Println("create dir fail", err)
	}

	if err = f.Close(); err != nil {
		log.Fatal("close file fail")
	}
	err = syscall.Mount("/proc/self/ns/net", nsPath, "", syscall.MS_BIND, "")
	if err != nil {
		log.Println("mount faild")
	}

	netns.Set(origns)

	// mv jail veth to new namespace
	nsfd, err := os.Open(nsPath)
	containerVeth, err := netlink.LinkByName(jailVethName)

	err = netlink.LinkSetNsFd(containerVeth, int(nsfd.Fd()))
	if err != nil {
		log.Println(err)
	}

	netns.Set(newns)

	// config namespace ip

	setIPaddress(jailVethName, "10.8.8.2/24")

	// up namespace loopback interface
	if lo, err := netlink.LinkByName("lo"); err == nil {
		if err := netlink.LinkSetUp(lo); err != nil {
			log.Println(err.Error())
		}
	}

	// configure namespace ip route, need to up interface first
	gatewayip, _, _ := net.ParseCIDR("10.8.8.1/24")

	route := &netlink.Route{
		Scope: netlink.SCOPE_UNIVERSE,
		Gw:    gatewayip,
	}
	netlink.RouteAdd(route)

	netns.Set(origns)

	setupEnviroment()

	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process packet here
		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			&ethLayer,
			&ipLayer,
			&tcpLayer,
		)
		foundLayerTypes := []gopacket.LayerType{}

		err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)
		if err != nil {
			continue
			//fmt.Println("Trouble decoding layers: ", err)
		}

		for _, layerType := range foundLayerTypes {
			if layerType == layers.LayerTypeIPv4 {
				fmt.Printf("IPv4: %-15s -> %-15s ", ipLayer.SrcIP, ipLayer.DstIP)
			}
			if layerType == layers.LayerTypeTCP {
				fmt.Printf("TCP Port: %6d ->  %6d ", tcpLayer.SrcPort, tcpLayer.DstPort)
				fmt.Printf("TCP SYN: %v | ACK: %v", tcpLayer.SYN, tcpLayer.ACK)
			}
		}
		fmt.Println()
	}
}

//add route https://github.com/teddyking/netsetgo/blob/0.0.1/configurer/container.go#L47-L53
//add ip https://github.com/teddyking/netsetgo/blob/0.0.1/configurer/container.go#L37
