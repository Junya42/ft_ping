all:
	gcc -g3 srcs/main.c -o ft_ping -lm

build:
	docker build -t debian-dev:latest .

run:
	docker run -it debian-dev:latest

clean:
	rm ft_ping

.PHONY: all build run clean
