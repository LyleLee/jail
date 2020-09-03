package jail

import (
	"log"

	"github.com/coreos/go-iptables/iptables"
)

func setupHostIptable() error {

	ipt, err := iptables.New()

	if err != nil {
		log.Fatal(err.Error())
	}

	has, err := ipt.Exists("nat", "POSTROUTING", "-s", "10.8.8.0/24", "!", "-o", "jaila", "-m", "comment", "--comment", "jail rule", "-j", "MASQUERADE")

	if err != nil {
		return err
	}

	if has == false {
		err := ipt.Append("nat", "POSTROUTING", "-s", "10.8.8.0/24", "!", "-o", "jaila", "-m", "comment", "--comment", "jail rule", "-j", "MASQUERADE")
		return err
	}

	has, err = ipt.Exists("filter", "FORWARD", "-i", "jaila", "-m", "comment", "--comment", "jail rule", "-j", "ACCEPT")

	if err != nil {
		return err
	}

	if has == false {
		err := ipt.Append("filter", "FORWARD", "-i", "jaila", "-m", "comment", "--comment", "jail rule", "-j", "ACCEPT")
		if err != nil {
			return err
		}
	}

	has, err = ipt.Exists("filter", "FORWARD", "-o", "jaila", "-m", "comment", "--comment", "jail rule", "-j", "ACCEPT")

	if err != nil {
		return err
	}

	if has == false {
		err := ipt.Append("filter", "FORWARD", "-o", "jaila", "-m", "comment", "--comment", "jail rule", "-j", "ACCEPT")
		return err
	}
	return nil
}

func cleanHostIptable() error {
	ipt, err := iptables.New()

	if err != nil {
		log.Fatal(err.Error())
	}

	has, err := ipt.Exists("nat", "POSTROUTING", "-s", "10.8.8.0/24", "!", "-o", "jaila", "-m", "comment", "--comment", "jail rule", "-j", "MASQUERADE")

	if err != nil {
		return err
	}

	if has == true {
		err := ipt.Delete("nat", "POSTROUTING", "-s", "10.8.8.0/24", "!", "-o", "jaila", "-m", "comment", "--comment", "jail rule", "-j", "MASQUERADE")
		return err
	}

	has, err = ipt.Exists("filter", "FORWARD", "-i", "jaila", "-m", "comment", "--comment", "jail rule", "-j", "ACCEPT")

	if err != nil {
		return err
	}

	if has == true {
		err := ipt.Delete("filter", "FORWARD", "-i", "jaila", "-m", "comment", "--comment", "jail rule", "-j", "ACCEPT")
		if err != nil {
			return err
		}
	}

	has, err = ipt.Exists("filter", "FORWARD", "-o", "jaila", "-m", "comment", "--comment", "jail rule", "-j", "ACCEPT")

	if err != nil {
		return err
	}

	if has == true {
		err := ipt.Delete("filter", "FORWARD", "-o", "jaila", "-m", "comment", "--comment", "jail rule", "-j", "ACCEPT")
		return err
	}
	return nil
}
