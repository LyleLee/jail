all:
	go build  -o jail.out ./cmd/jail/main.go
clean:
	rm jail.out
run: all
	sudo ./jail.out curl www.baidu.com
testbaidu:
	sudo ip netns exec jailns curl www.baidu.com
