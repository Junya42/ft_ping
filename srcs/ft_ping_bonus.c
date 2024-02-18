#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>

char *get_right_icmp_error(int type, int code);

typedef struct s_icmp
{
    struct icmphdr hdr;
    char packet[64];
} t_icmp;

#define PACKET_SIZE 64

// Structure for ICMP header
struct icmphdr
{
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	unsigned short id;
	unsigned short seq;
};

struct ipheader
{
	unsigned char ihl : 4,
		version : 4;
	unsigned char tos;
	unsigned short tot_len;
	unsigned short id;
	unsigned short frag_off;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short check;
	unsigned int saddr;
	unsigned int daddr;
};

// Function to calculate the checksum for ICMP header
unsigned short checksum(void *b, int len)
{
	unsigned short *buf = b;
	unsigned int sum = 0;
	unsigned short result;

	for (sum = 0; len > 1; len -= 2)
		sum += *buf++;

	if (len == 1)
		sum += *(unsigned char *)buf;

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;

	return result;
}

int sockfd = -1;
char *target = NULL;
unsigned long transmitted = 0;
unsigned long received = 0;
double min = __DBL_MAX__;
double avg = 0.0;
double max = __DBL_MIN__;
double sum_of_squares = 0;
double mdev = 0.0;
int l_pipe = 0;
struct timeval total;

void sighandler(int sig)
{

	(void)sig;

	struct timeval total_end;

	gettimeofday(&total_end, NULL);
	long secs_diff = total_end.tv_sec - total.tv_sec;
    long usecs_diff = total_end.tv_usec - total.tv_usec;

        if (usecs_diff < 0)
        {
            // Adjust for the fact that usecs_diff is negative
            --secs_diff;
            usecs_diff += 1000000; // Add one second in microseconds
        }

    unsigned long total_time = (unsigned long)secs_diff * 1000 + (unsigned long)usecs_diff / 1000;

	double loss = 100.0 - (100.0 * (received) / transmitted);

	printf("\n--- %s ping statistics ---\n", target);
	printf("%lu packets transmitted, %lu received, %f%% packet loss, time %ldms\n",
		   transmitted, received, loss,
		   total_time);
	if (l_pipe < 2)
		printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", min, avg, max, mdev);
	else
		printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms, pipe %d\n", min, avg, max, mdev, l_pipe);
	close(sockfd);
	exit(sig);
}

struct option
{
	int f;	  // ok ? ipg/ewma ?
	double i; // ok
	int l;	  // ok
	int n;	  // ok
	int p;	  // how ?
	int r;	  // depends on OS
	int s;	  // ok
	int ttl;  // ok i guess ?
	int T;
	int v;	  //?
	int w;	  // ok
	double W; // ok
	int help; // ok
};

void check_options(struct option *opt, char **av)
{

	char check = 0;
	int i_check = 0;
	opt->i = 1;
	opt->s = PACKET_SIZE;
	opt->ttl = 64;
	opt->W = 10;
	int sudo = getuid() == 0 ? 1 : 0;
	for (int i = 1; av[i]; i++)
	{

		if (av[i][0] == '-' && check == 0)
		{
			for (int j = 1; av[i][j]; j++)
			{

				if (check != 0)
				{
					fprintf(stderr, "ft_ping: invalid argument: '%c'\n", av[i][j]);
					exit(1);
				}
				switch (av[i][j])
				{
				case 'f':
					opt->f = 1;
					break;
				case 'i':
					check = 'i';
					i_check = 1;
					break;
				case 'l':
					check = 'l';
					break;
				case 'n':
					opt->n = 1;
					break;
				case 'p':
					check = 'p';
					break;
				case 'r':
					opt->r = 1;
					break;
				case 's':
					check = 's';
					break;
				case 't':
					check = 't';
					break;
				case 'T':
					opt->T = 1;
					break;
				case 'v':
					opt->v = 1;
					break;
				case 'w':
					check = 'w';
					break;
				case 'W':
					check = 'W';
					break;
				case 'h':
					opt->help = 1;
					break;
				case '?':
					opt->help = 1;
					break;
				default:
					// Handle unrecognized option
					break;
				}
			}
		}
		else if (av[i][0] == '-')
		{
			fprintf(stderr, "ft_ping: invalid argument: '%s'\n", av[i]);
			exit(1);
		}
		else if (check)
		{

			int value = atoi(av[i]);

			switch (check)
			{
			case 'i':
				opt->i = atof(av[i]);
				if (!sudo && opt->i < 0.20)
				{
					fprintf(stderr, "ft_ping: cannot flood; minimal interval allowed for user is 200ms\n");
					exit(1);
				}
				break;
			case 'l':
				if (value < 0 || value > 65536)
				{
					fprintf(stderr, "ft_ping: invalid argument: '%d': out of range: 1 <= value <= 65536\n", value);
					exit(1);
				}
				if (!sudo)
				{
					if (value > 3)
					{
						fprintf(stderr, "ft_ping: cannot set preload to value greater than 3: %d\n", value);
						exit(1);
					}
				}
				else if (value > 1)
				{
					opt->l = value;
					l_pipe = value;
				}
				break;
			case 'p':
				opt->p = value;
				break;
			case 's':
				opt->s = value + 8;
				break;
			case 't':
				if (value < 0 || value > 255)
				{
					fprintf(stderr, "ft_ping: invalid argument: '%d': out of range: 0 <= value <= 255\n", value);
					exit(1);
				}
				opt->ttl = value;
				break;
			case 'w':
				opt->w = value;
				break;
			case 'W':
				opt->W = atof(av[i]);
				if (opt->W < 0.001)
				{
					fprintf(stderr, "ft_ping: bad linger time: %f\n", opt->W);
					exit(1);
				}
				break;
			}
			check = 0;
		}
		else
		{
			if (!target)
				target = av[i];
		}
	}

	if (check)
	{
		fprintf(stderr, "ft_ping: option requires an argument -- '%c'\n", check);
		exit(1);
	}
	if (opt->f && i_check == 0)
	{
		opt->i = 0;
	}
	/*printf("opt->f: %d\n", opt->f);
	printf("opt->i: %f\n", opt->i);
	printf("opt->l: %d\n", opt->l);
	printf("opt->n: %d\n", opt->n);
	printf("opt->p: %d\n", opt->p);
	printf("opt->r: %d\n", opt->r);
	printf("opt->s: %d\n", opt->s);
	printf("opt->ttl: %d\n", opt->ttl);
	printf("opt->T: %d\n", opt->T);
	printf("opt->v: %d\n", opt->v);
	printf("opt->w: %d\n", opt->w);
	printf("opt->W: %f\n", opt->W);
	printf("opt->help: %d\n", opt->help);
	printf("sudo = %d\n", sudo);*/
}

void help(void)
{

	printf("\nUsage\n");
	printf("	ft_ping [options] <destination>\n\n");
	printf("Options:\n");
	printf("	<destination>		dns name or ip address\n");
	printf("	-f			flood ping\n");
	printf("	-i <interval>		seconds between sending each packet\n");
	printf("	-l <preload>		send <preload> number of packages while waiting replies\n");
	printf("	-n			no dns name resolution\n");
	printf("	-p <pattern>		fill packet with <pattern>\n");
	printf("	-r			bypass routing\n");
	printf("	-s <size>		use <size> data bytes\n");
	printf("	-t <ttl>		set ttl to <ttl>\n");
	printf("	-v			verbose output\n");
	printf("	-w <deadline>		reply wait <deadline> in seconds\n");
	printf("	-W <timeout>		time to wait for response\n");
	printf("	-h			print help and exit\n");
	printf("	-?			print help and exit\n");
	exit(0);
}

void build_request(t_icmp *req, int seq)
{
    bzero(req, sizeof(req));
    req->hdr.type = ICMP_ECHO;
    req->hdr.code = 0;
    req->hdr.un.echo.id = getpid();
    req->hdr.un.echo.sequence = htons(seq);
    req->hdr.checksum = 0;
    req->hdr.checksum = checksum(req, sizeof(req));
    bzero(req->packet, sizeof(req->packet));
}

uint32_t get_ip(char *iface)
{
	int fd;
	struct ifreq ifr = {0};

	char ip[INET_ADDRSTRLEN];
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFADDR, &ifr) == -1)
	{
		perror("SIOCGIFADDR");
		close(fd);
		exit(EXIT_FAILURE);
	}
	inet_ntop(AF_INET, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, ip, sizeof(ip));

	printf("IP address of %s: %s\n", iface, ip);
	close(fd);

	return ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
}

uint32_t get_netmask(char *iface)
{
	int fd;
	struct ifreq ifr = {0};
	char ip[INET_ADDRSTRLEN];
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFNETMASK, &ifr) == -1)
	{
		perror("SIOCGIFNETMASK");
		close(fd);
		exit(EXIT_FAILURE);
	}
	inet_ntop(AF_INET, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, ip, sizeof(ip));

	printf("MASK of %s: %s\n", iface, ip);
	close(fd);

	return ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr;
}

int main(int argc, char **argv)
{
	if (argc < 2)
	{
		printf("Usage: %s <hostname/IP>\n", argv[0]);
		return 1;
	}

	struct option opt = {0};
	check_options(&opt, argv);

	if (opt.help)
		help();

	struct addrinfo hints, *res;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_ICMP;

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sockfd < 0)
	{
		perror("Unable to create socket");
		return 1;
	}

	struct timeval timeout;
	timeout.tv_sec = (int)opt.W;
	timeout.tv_usec = (opt.W - timeout.tv_sec) * 1000000;

	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
	{
		perror("setsockopt timeout");
		close(sockfd);
		return 1;
	}

	if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &opt.ttl, sizeof(opt.ttl)) < 0)
	{
		perror("setsockopt ttl");
		close(sockfd);
		return 1;
	}

	if (getaddrinfo(target, NULL, &hints, &res) != 0)
	{
		fprintf(stderr, "ft_ping: unknown host\n");
		close(sockfd);
		return 1;
	}

	struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;

	uint32_t my_ip = get_ip("eth0");
	uint32_t my_netmask = get_netmask("eth0");
	uint32_t target_ip = inet_addr(inet_ntoa(addr->sin_addr));

	// printf("%s\n", inet_ntoa(addr->sin_addr));
	// printf("my_ip = %u >>> target_ip = %u\n", my_ip, target_ip);
	if (((my_ip & my_netmask) == (target_ip & my_netmask)))
	{
		printf("The target IP is on the same network.\n");
	}
	else
	{
		printf("The target IP is NOT on the same network.\n");
		if (opt.r)
		{
			close(sockfd);
			return 1;
		}
	}

	int seq = 0;
	char packet[opt.s];
	struct icmphdr *icmp = (struct icmphdr *)packet;

	icmp->type = 8; // ICMP Echo Request
	icmp->code = 0;
	icmp->id = htons(getpid());
	icmp->checksum = 0;

	gettimeofday(&total, NULL);
	signal(SIGINT, sighandler);
	// Ping loop

	if (!opt.v)
		printf("FT_PING %s (%s) %d(%d) bytes of data.\n", target, inet_ntoa(addr->sin_addr), opt.s - 8, opt.s + 20);
	else
		printf("FT_PING %s (%s) %d(%d) bytes of data, id 0x0%x = %i.\n", target, inet_ntoa(addr->sin_addr), opt.s - 8, opt.s + 20, getpid(), getpid());
	while (--opt.l >= 0)
	{
		icmp->seq = htons(++seq);
		icmp->checksum = 0;
		gettimeofday((struct timeval *)(packet + 8), NULL);
		struct ipheader *ip_head = (struct ipheader *)packet;
		ip_head->ttl = opt.ttl;
		icmp->checksum = checksum(ip_head, sizeof(struct ipheader));

		struct timeval start;
		struct timeval end;
		// Send ICMP packet
		gettimeofday(&start, NULL);
		if (sendto(sockfd, packet, opt.s, 0, (struct sockaddr *)addr, sizeof(struct sockaddr)) == -1)
		{
			perror("sendto");
			close(sockfd);
			return 1;
		}
		transmitted++;
		// Receive ICMP packet
		char recv_buf[opt.s];
		struct iovec iov[1];
		iov[0].iov_base = recv_buf;
		iov[0].iov_len = sizeof(recv_buf);

		struct sockaddr_in sender_addr;
		socklen_t sender_addr_len = sizeof(sender_addr);
		struct msghdr msg;
		memset(&msg, 0, sizeof(msg));
		msg.msg_name = &sender_addr;
		msg.msg_namelen = sender_addr_len;
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		// int recv_len = recvfrom(sockfd, recv_buf, opt.s, 0, (struct sockaddr *)&sender_addr, &sender_addr_len);
		int recv_len = recvmsg(sockfd, &msg, 0);

		if (recv_len < 0)
		{
			printf("%d\n", errno);
			perror("recvfrom");
			close(sockfd);
			return 1;
		}
		gettimeofday(&end, NULL);
		received++;
		struct ipheader *ip = (struct ipheader *)recv_buf;
		unsigned char ttl = ip->ttl;
		struct timeval *recv_time = (struct timeval *)(recv_buf + 8);
		double process_time = (double)(end.tv_sec - start.tv_sec) * 1000.0 + (double)(end.tv_usec - start.tv_usec) / 1000.0;
		if (min > process_time)
			min = process_time;
		if (max < process_time)
			max = process_time;
		avg = ((avg * (received - 1)) + process_time) / (received);
		sum_of_squares = ((sum_of_squares * (received - 1)) + process_time * process_time) / received;
		if (received > 1)
		{
			mdev = sqrt(sum_of_squares - avg * avg);
		}

		if (!opt.n)
		{
			printf("%d bytes from %s (%s): icmp_seq=%d ttl=%u time=%.2f ms\n",
				   recv_len, argv[1], inet_ntoa(sender_addr.sin_addr), ntohs(icmp->seq),
				   ttl, process_time);
		}
		else
		{
			printf("%d bytes from %s: icmp_seq=%d ttl=%u time=%.2f ms\n",
				   recv_len, inet_ntoa(sender_addr.sin_addr), ntohs(icmp->seq),
				   ttl, process_time);
		}

		if (opt.w)
		{
			struct timeval total_end;
			gettimeofday(&total_end, NULL);

			if ((unsigned long)(total_end.tv_sec - total.tv_sec) >= opt.w)
			{
				sighandler(0);
			}
		}
	}
	while (1)
	{
		icmp->seq = htons(++seq);
		icmp->checksum = 0;
		// struct ipheader *ip_head = (struct ipheader *)packet; //doesnt work with opt.i
		// ip_head->ttl = opt.t; //doesnt work with opt.i
		gettimeofday((struct timeval *)(packet + 8), NULL);
		// icmp->checksum = checksum(ip_head, sizeof(struct ipheader)); //doesnt work with opt.i
		icmp->checksum = checksum(packet, opt.s);

		struct timeval start;
		struct timeval end;
		// Send ICMP packet
		gettimeofday(&start, NULL);
		if (sendto(sockfd, packet, opt.s, 0, (struct sockaddr *)addr, sizeof(struct sockaddr)) == -1)
		{
			perror("sendto");
			close(sockfd);
			return 1;
		}
		if (opt.f)
		{
			fflush(stdout);
			printf(".");
		}
		transmitted++;
		// Receive ICMP packet
		char recv_buf[opt.s];
		struct iovec iov[1];
		iov[0].iov_base = recv_buf;
		iov[0].iov_len = sizeof(recv_buf);
		struct sockaddr_in sender_addr;
		socklen_t sender_addr_len = sizeof(sender_addr);
		struct msghdr msg;
		memset(&msg, 0, sizeof(msg));
		msg.msg_name = &sender_addr;
		msg.msg_namelen = sender_addr_len;
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		// int recv_len = recvfrom(sockfd, recv_buf, opt.s, 0, (struct sockaddr *)&sender_addr, &sender_addr_len);
		int recv_len = recvmsg(sockfd, &msg, 0);

		if (recv_len > -1)
		{
			received++;
		}
		if (opt.f)
		{
			fflush(stdout);
			printf("\b");
		}
		gettimeofday(&end, NULL);
		struct ipheader *ip = (struct ipheader *)recv_buf;
		unsigned char ttl = ip->ttl;
		struct timeval *recv_time = (struct timeval *)(recv_buf + 8);
		double process_time = (double)(end.tv_sec - start.tv_sec) * 1000.0 + (double)(end.tv_usec - start.tv_usec) / 1000.0;
		if (min > process_time)
			min = process_time;
		if (max < process_time)
			max = process_time;
		avg = ((avg * (received - 1)) + process_time) / (received);
		sum_of_squares = ((sum_of_squares * (received - 1)) + process_time * process_time) / received;
		if (received > 1)
		{
			mdev = sqrt(sum_of_squares - avg * avg);
		}

		if (!opt.f)
		{

			if (!opt.n)
			{
				printf("%d bytes from %s (%s): icmp_seq=%d ", recv_len, argv[1], inet_ntoa(sender_addr.sin_addr), ntohs(icmp->seq));

				if (strcmp(inet_ntoa(sender_addr.sin_addr), inet_ntoa(addr->sin_addr)) == 0)
				{
					printf("ttl=%u time=%.2f ms\n", ttl, process_time);
				}
				else
				{
					printf("Time to live exceeded\n");
				}
			}
			else
			{
				printf("%d bytes from %s: icmp_seq=%d ", recv_len, inet_ntoa(sender_addr.sin_addr), ntohs(icmp->seq));

				if (strcmp(inet_ntoa(sender_addr.sin_addr), inet_ntoa(addr->sin_addr)) == 0)
				{
					printf("ttl=%u time=%.2f ms\n", ttl, process_time);
					printf("%s\n", inet_ntoa(sender_addr.sin_addr));
					printf("%s\n", inet_ntoa(addr->sin_addr));
				}
				else
				{
					printf("Time to live exceeded\n");
				}
			}
		}

		if (opt.w)
		{
			struct timeval total_end;
			gettimeofday(&total_end, NULL);

			if ((unsigned long)(total_end.tv_sec - total.tv_sec) >= opt.w)
			{
				sighandler(0);
			}
		}
		usleep(opt.i * 1000000); // Delay between pings
	}

	freeaddrinfo(res);
	close(sockfd);

	return 0;
}