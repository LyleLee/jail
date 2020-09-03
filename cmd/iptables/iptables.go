package main

import (
	"fmt"
	"log"

	"github.com/coreos/go-iptables/iptables"
)

func main() {
	ipt, err := iptables.New()

	if err != nil {
		log.Fatal(err.Error())
	}


	has, err := ipt.Exists("nat", "POSTROUTING", "-s", "10.8.8.0/24", "!", "-o", "jaila", "-m", "comment", "--comment", "jail rule", "-j", "MASQUERADE")

	if err != nil {
		log.Println(err.Error())
	}

	if has == false {
		err := ipt.Append("nat", "POSTROUTING", "-s", "10.8.8.0/24", "!", "-o", "jaila", "-m", "comment", "--comment", "jail rule", "-j", "MASQUERADE")
		if err != nil {
			log.Println(err.Error())
		}
	}

	has, err = ipt.Exists("filter", "FORWARD", "-i", "jaila", "-m", "comment", "--comment", "jail rule", "-j", "ACCEPT")

	if err != nil {
		log.Println(err.Error())
	}

	if has == false {
		err := ipt.Append("filter", "FORWARD", "-i", "jaila", "-m", "comment", "--comment", "jail rule", "-j", "ACCEPT")
		if err != nil {
			log.Println(err.Error())
		}
	}

	has, err = ipt.Exists("filter", "FORWARD", "-o", "jaila", "-m", "comment", "--comment", "jail rule", "-j", "ACCEPT")

	if err != nil {
		log.Println(err.Error())
	}

	if has == false {
		err := ipt.Append("filter", "FORWARD", "-o", "jaila", "-m", "comment", "--comment", "jail rule", "-j", "ACCEPT")
		if err != nil {
			log.Println(err.Error())
		}
	}
}
