#!/bin/bash
set -x

jaila=jaila
jailb=jailb
jailns=jailns

sudo iptables -t nat -D POSTROUTING -s 10.8.8.0/24 ! -o $jaila -j MASQUERADE
sudo iptables -D FORWARD -i $jaila -j ACCEPT
sudo iptables -D FORWARD -o $jaila -j ACCEPT
sudo iptables -t nat -A POSTROUTING -s 10.8.8.0/24 ! -o $jaila -j MASQUERADE
sudo iptables -A FORWARD -i $jaila -j ACCEPT
sudo iptables -A FORWARD -o $jaila -j ACCEPT

if [ ! -d /etc/netns/$jailns/resolv.conf ]; then
	sudo mkdir -p /etc/netns/$jailns
fi

echo "nameserver 114.114.114.114" | sudo tee /etc/netns/$jailns/resolv.conf
