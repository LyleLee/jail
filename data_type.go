package main

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

//map["8.8.8.8"]["udp"][53].xxx
var Keeper map[string]map[string]map[int]packetCounter
