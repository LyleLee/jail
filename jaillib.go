package jail

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/docker/docker/pkg/reexec"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

/*
8.8.8.8
    53, udp, revice 4 packets, 100 B, send 10 packets, 200 Bytes
220.181.38.150
    80, udp, revice 4 packets, 100 B, send 10 packets, 200 Bytes
    443, udp, revice 4 packets, 100 B, send 10 packets, 200 Bytes
23.16.1.18
    80, udp, revice 4 packets, 100 B, send 10 packets, 200 Bytes
    443, udp, revice 4 packets, 100 B, send 10 packets, 200 Bytes
    0, icmp, revice 4 packets, 100 B, send 10 packets, 200 Bytes

*/

type packetCounter struct {
	receiveCount int64
	receiveByte  int64
	sendCount    int64
	sendByte     int64
}

// Keeper map["8.8.8.8"]["udp"][53].xxx
var Keeper map[string]map[string]map[int]packetCounter

var (
	hostVethName string = "jaila"
	jailVethName string = "jailb"
	nsName       string = "jailns"
	device       string = hostVethName
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
	ethLayer     layers.Ethernet
	ipLayer      layers.IPv4
	tcpLayer     layers.TCP
)
var wg sync.WaitGroup

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	reexec.Register("nsInit", nsInit)
	if reexec.Init() {
		os.Exit(0)
	}
}

func setupEnviroment() {
	if err := cleanInterface(); err != nil {
		log.Println(err.Error())
	}
	if err := cleanNamespace(); err != nil {
		log.Printf(err.Error())
	}
	if err := addVethPair(); err != nil {
		log.Fatal(err.Error())
	}

	if err := setupHostVeth(); err != nil {
		log.Fatal(err.Error())
	}

	if err := setupNamespace(); err != nil {
		log.Fatal(err.Error())
	}
}

func setupNamespace() error {
	cmd := reexec.Command("nsInit")

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNS |
			syscall.CLONE_NEWUTS |
			syscall.CLONE_NEWIPC |
			syscall.CLONE_NEWPID |
			syscall.CLONE_NEWNET |
			syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: 0,
				HostID:      os.Getegid(),
				Size:        1,
			},
		},
		GidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: 0,
				HostID:      os.Getegid(),
				Size:        1,
			},
		},
	}

	if err := cmd.Start(); err != nil {
		log.Println("Error running reexec.command:", err.Error())
		os.Exit(1)
	}

	if err := moveVethToContainer(cmd.Process.Pid); err != nil {
		log.Println("Erorr when moving veth to container")
		return err
	}

	if err := setupHostIptable(); err != nil {
		return err
	}

	if err := cmd.Wait(); err != nil {
		log.Println("Error at waiting for /proc/self/exec")
		os.Exit(1)
	}

	return nil
}

func moveVethToContainer(namespacePID int) error {
	containerVethLink, err := netlink.LinkByName(jailVethName)

	if err != nil {
		return err
	}

	return netlink.LinkSetNsPid(containerVethLink, namespacePID)
}

func setupHostVeth() error {
	if err := setIPaddress(hostVethName, "10.8.8.1/24"); err != nil {
		return err
	}
	return nil
}

func nsInit() {
	// set up

	log.Println("begin setup namespace ...")
	if err := setIPaddress(jailVethName, "10.8.8.2/24"); err != nil {
		log.Fatal(err.Error())
	}

	// up namespace loopback interface
	if lo, err := netlink.LinkByName("lo"); err == nil {
		if err := netlink.LinkSetUp(lo); err != nil {
			log.Println(err.Error())
		}
	}

	gatewayip, _, _ := net.ParseCIDR("10.8.8.1/24")

	route := &netlink.Route{
		Scope: netlink.SCOPE_UNIVERSE,
		Gw:    gatewayip,
	}
	netlink.RouteAdd(route)

	log.Println("finish setup namespace")

	nsRun()
}

func nsRun() {
	//panic("panic from func nsRun()")
	cmd := exec.Command("/bin/sh")

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.Env = []string{"PS1=-[ns-process]- # "}

	if err := cmd.Run(); err != nil {
		fmt.Printf("Error running the /bin/sh command - %s\n", err)
		os.Exit(1)
	}
}
func addVethPair() error {
	vethLinkAttrs := netlink.NewLinkAttrs()
	vethLinkAttrs.Name = hostVethName

	veth := &netlink.Veth{
		LinkAttrs: vethLinkAttrs,
		PeerName:  jailVethName,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		return err
	}
	return nil
}

func jailStart() {

}

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
func checkSudo() {
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

func removeLinkExist(vethName string) error {
	vethLink, err := netlink.LinkByName(vethName)
	if err != nil && err.Error() == "Link not found" {
		log.Println("Link not found")
		return nil
	}
	if vethLink == nil {
		log.Println("Get Link empty")
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

func cleanInterface() error {
	if err := removeLinkExist(hostVethName); err != nil {
		return err
	}
	if err := removeLinkExist(jailVethName); err != nil {
		return err
	}
	return nil
}

func cleanNamespace() error {
	log.Println("deleting a namespace:", nsName)
	if err := netns.DeleteNamed(nsName); err != nil {
		log.Println(err.Error())
		log.Println("deleting a namespace failed:", nsName)
		return err
	}
	return nil
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

func startCapture() error {

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
				fmt.Printf("TCP SYN: %5v | ACK: %5v", tcpLayer.SYN, tcpLayer.ACK)
			}
		}
		fmt.Println()
	}
	wg.Done()
	return nil
}

func executeCommand(cmdString string) {
	cmd := exec.Command("bash", "-c", cmdString)
	fmt.Println(cmd.String())
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(string(output))
}

/*
func main() {

	pid := flag.Int("pid", -1, "program's pid")

	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	checkSudo()
	cleanInterfaceNamespace()


	// configure host jail veth ip
	setIPaddress(hostVethName, "10.8.8.1/24")

	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save the current network namespace
	origns, _ := netns.Get()
	defer origns.Close()

	newns, err := netns.NewNamed(nsName)
	if err != nil {
		log.Fatalln(err.Error())
	}
	defer newns.Close()

	netns.Set(origns)

	// mv jail veth to new namespace
	//nsfd, err := os.Open(nsPath)
	containerVeth, err := netlink.LinkByName(jailVethName)

	err = netlink.LinkSetNsFd(containerVeth, int(newns))
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

	if err := syscall.Mount("/etc/netns/jailns/resolv.conf", "/etc/resolv.conf", "", syscall.MS_BIND, ""); err != nil {
		log.Println(err.Error())
	}

	netns.Set(origns)

	executeCommand("./iptables_setting.sh")
	wg.Add(1)
	go startCapture()
	time.Sleep(1000 * time.Millisecond)

	netns.Set(newns)

	if *pid != -1 {
		//
	} else if *pid == -1 && len(flag.Args()) > 0 {
		executeCommand("ip address list")
		executeCommand("cat /etc/resolv.conf")
		executeCommand("ping -c 3 www.baidu.com")
		executeCommand(strings.Join(flag.Args(), " "))
	} else if *pid == -1 && len(flag.Args()) == 0 {
		//do nothing
	} else {
		//do nothing
	}
	netns.Set(origns)

	wg.Wait()
	fmt.Println("program finish")
}

*/

// add route https://github.com/teddyking/netsetgo/blob/0.0.1/configurer/container.go#L47-L53
// add ip https://github.com/teddyking/netsetgo/blob/0.0.1/configurer/container.go#L37
// write pcap file https://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket#write-pcap-file
// namespace basic https://medium.com/@teddyking/namespaces-in-go-network-fdcf63e76100
// golang context timeout https://medium.com/@vCabbage/go-timeout-commands-with-os-exec-commandcontext-ba0c861ed738
