bonus:
	gcc srcs/ft_ping_bonus.c -o ft_ping_bonus -lm

ping:
	gcc srcs/ft_ping.c -o ft_ping -lm

.PHONY: bonus ping
