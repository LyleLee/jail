package jail

import (
	"log"
)

// JailInit To init the namespace and veth pair, nework route enviroments
func JailInit() {
}

// TrapPID Trap program traffic by PID
func TrapPID() {
	log.Println("Trap program traffic by PID")
}

// TrapCommandLine Trap program traffic by spwn a process from command lin
func TrapCommandLine(str string) {
	log.Println("Trap program traffic by spwn a process from command line")
	log.Println("command line is: ", str)
}
