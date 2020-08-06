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

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

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

// CreateNamespace to create a new namespace
func CreateNamespace(nsName string) (string, error) {

	netnsDir := "/var/run/netns"
	_, err := os.Stat(netnsDir)
	if err != nil {
		log.Println("cannot find ", netnsDir, "perhaps your kernel need en upgrade")
		return "", err
	}

	netnsDirPath := filepath.Join(netnsDir, nsName)
	f, err := os.Create(netnsDirPath)
	if err != nil {
		log.Println("create dir fail", err)
		return "", err
	}

	if err = f.Close(); err != nil {
		log.Println("close file fail")
		return "", err
	}
	err = syscall.Mount("/proc/self/ns/net", netnsDirPath, "", syscall.MS_BIND, "")
	if err != nil {
		log.Println("mount faild")
		return "", err
	}
	return netnsDirPath, nil
}

func main() {
	// Lock the OS Thread so we don't accidentally switch namespaces

	CheckSudo()

	prefix := NewJailInterface()

	if prefix == "" {
		log.Fatal("get new interface fail")
	}

	hostVethName := fmt.Sprintf("%sa", prefix)
	jailVethName := fmt.Sprintf("%sb", prefix)
	vethLinkAttrs := netlink.NewLinkAttrs()
	vethLinkAttrs.Name = hostVethName

	veth := &netlink.Veth{
		LinkAttrs: vethLinkAttrs,
		PeerName:  jailVethName,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		log.Fatal("fail to add veth pair")
	}

	if err := netlink.LinkSetUp(veth); err != nil {
		log.Fatal("fail to ip link set $(link) up")
	}

	containerVeth, err := netlink.LinkByName(jailVethName)
	if err != nil {
		log.Fatal("cannot get link from veth")
	}

	log.Println("get interface:", containerVeth)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save the current network namespace
	origns, _ := netns.Get()
	defer origns.Close()

	newns, _ := netns.New()
	defer newns.Close()

	nsPath := filepath.Join("/var/run/netns", "ns8")
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

	nsfd, err := os.Open(nsPath)

	err = netlink.LinkSetNsFd(containerVeth, int(nsfd.Fd()))
	if err != nil {
		log.Println(err)
	}
	ifaces, _ := net.Interfaces()
	fmt.Printf("Interfaces: %v\n", ifaces)

}

//add route https://github.com/teddyking/netsetgo/blob/0.0.1/configurer/container.go#L47-L53
//add ip https://github.com/teddyking/netsetgo/blob/0.0.1/configurer/container.go#L37
