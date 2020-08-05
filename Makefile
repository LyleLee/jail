all:
	go build -o jail.out .
clean:
	rm jail.out
run: all
	./jail.out