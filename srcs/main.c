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
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
//#include <libnl3/netlink/netlink-compat.h>

char *icmp_error_to_string(int type, int code)
{
	switch (type)
	{
	case ICMP_DEST_UNREACH:
		switch (code)
		{
		case ICMP_NET_UNREACH:
			return "Destination Net Unreachable\n";
		case ICMP_HOST_UNREACH:
			return "Destination Host Unreachable\n";
		case ICMP_PROT_UNREACH:
			return "Destination Protocol Unreachable\n";
		case ICMP_PORT_UNREACH:
			return "Destination Port Unreachable\n";
		case ICMP_FRAG_NEEDED:
			return "Frag needed\n";
		case ICMP_SR_FAILED:
			return "Source Route Failed\n";
		case ICMP_NET_UNKNOWN:
			return "Destination Net Unknown\n";
		case ICMP_HOST_UNKNOWN:
			return "Destination Host Unknown\n";
		case ICMP_HOST_ISOLATED:
			return "Source Host Isolated\n";
		case ICMP_NET_ANO:
			return "Destination Net Prohibited\n";
		case ICMP_HOST_ANO:
			return "Destination Host Prohibited\n";
		case ICMP_NET_UNR_TOS:
			return "Destination Net Unreachable for Type of Service\n";
		case ICMP_HOST_UNR_TOS:
			return "Destination Host Unreachable for Type of Service\n";
		case ICMP_PKT_FILTERED:
			return "Packet filtered\n";
		case ICMP_PREC_VIOLATION:
			return "Precedence Violation\n";
		case ICMP_PREC_CUTOFF:
			return "Precedence Cutoff\n";
		default:
			return "Dest Unreachable";
		}
	case ICMP_SOURCE_QUENCH:
		return "Source Quench\n";
	case ICMP_REDIRECT:
		switch (code)
		{
		case ICMP_REDIR_NET:
			return "Redirect Network";
		case ICMP_REDIR_HOST:
			return "Redirect Host";
		case ICMP_REDIR_NETTOS:
			return "Redirect Type of Service and Network";
		case ICMP_REDIR_HOSTTOS:
			return "Redirect Type of Service and Host";
		default:
			return "Redirect Errors";
		}
	case ICMP_TIME_EXCEEDED:
		switch (code)
		{
		case ICMP_EXC_TTL:
			return "Time to live exceeded";
		case ICMP_EXC_FRAGTIME:
			return "Fragment Reass time exceeded";
		default:
			return "TTL Errors";
		}
	}
	return "Unknown ICMP Error";
}

#define PACKET_SIZE 64
#define IP_HDR_SIZE sizeof(struct iphdr)
#define ICMP_HDR_SIZE sizeof(struct icmphdr)
#define ICMP_BODY_SIZE 56

// Function to calculate the checksum for ICMP header
unsigned short checksum(void *b, int len)
{
	unsigned short *buf = b;
	unsigned int sum = 0;
	unsigned short result;

	for (sum = 0; len > 1; len -= 2)
		sum += *buf++;

	   if (len ==   1)
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
struct addrinfo *res;

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
	printf("%lu packets transmitted, %lu packets received, %d%% packet loss\n",
		   transmitted, received, (int)loss);

	if (received > 0)
	{
		// if (l_pipe < 2)
		printf("round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n", min, avg, max, mdev);
		// else
		// printf("round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms, pipe %d\n", min, avg, max, mdev, l_pipe);
	}
	freeaddrinfo(res);
	close(sockfd);
	exit(sig);
}

struct option
{
	int f;	  // ok
	double i; // ok
	int l;	  // ok
	int n;	  // ok
	int r;	  // depends on OS
	int s;	  // ok
	int ttl;  // ok ?
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
	opt->s = PACKET_SIZE;
	int sudo = getuid() == 0 ? 1 : 0;
	for (int i = 1; av[i]; i++)
	{

		if (av[i][0] == '-' && check == 0)
		{
			if (strlen(av[i]) == 1)
			{
				printf("ft_ping: %s: Name or service not known\n", av[i]);
				exit(1);
			}
			for (int j = 1; av[i][j]; j++)
			{

				if (check != 0)
				{
					fprintf(stderr, "ft_ping: invalid argument: '%c'\n", av[i][j]);
					exit(1);
				}
				if (strcmp(av[i], "--ttl") == 0)
				{
					check = 't';
					break;
				}
				if (strcmp(av[i], "--help") == 0)
				{
					opt->help = 1;
					break;
				}
				if (strcmp(av[i], "--version") == 0)
				{
					printf("ft_ping (42 ft_ping) 1.0\n");
					printf("Copyright (C) 2024 Student Project, Inc.\n");
					printf("No license required\n");
					printf("This is free software: you are free to change and redistribute it.\n");
					printf("There is NO WARRANTY, to the extent permitted by law.\n\n");
					printf("Written by anremiki.\n");
					exit(0);
				}
				if (strcmp(av[i], "--flood") == 0)
				{
					opt->f = 1;
					break;
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
				case 'V':
					printf("ft_ping (42 ft_ping) 1.0\n");
					printf("Copyright (C) 2024 Student Project, Inc.\n");
					printf("No license required\n");
					printf("This is free software: you are free to change and redistribute it.\n");
					printf("There is NO WARRANTY, to the extent permitted by law.\n\n");
					printf("Written by anremiki.\n");
					exit(0);
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
			if (strlen(av[i]) == 1)
			{
				printf("ft_ping: %s: Name or service not known\n", av[i]);
				exit(1);
			}
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
	printf("	-r			bypass routing\n");
	printf("	-s <size>		use <size> data bytes\n");
	printf("	-ttl <ttl>		set ttl to <ttl>\n");
	printf("	-v			verbose output\n");
	printf("	-w <deadline>		reply wait <deadline> in seconds\n");
	printf("	-W <timeout>		time to wait for response\n");
	printf("	-V			print program version\n");
	printf("	-h			print help and exit\n");
	printf("	-?			print help and exit\n");
	exit(0);
}

struct option opt = {0};

void build_request(char *req, int seq, int size)
{


	bzero(req, size);
	struct icmphdr *request = (struct icmphdr *)req;

	request->type = ICMP_ECHO;
	request->un.echo.id = htons(getpid());
	request->un.echo.sequence = seq;
	request->checksum = checksum((unsigned short *)request, sizeof(req));
}

int main(int argc, char **argv)
{
	if (argc < 2)
	{
		printf("Usage: %s <hostname/IP>\n", argv[0]);
		return 1;
	}

	check_options(&opt, argv);

	if (opt.help)
		help();

	struct addrinfo hints;

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

	int seq = 0;

	gettimeofday(&total, NULL);
	signal(SIGINT, sighandler);
	// Ping loop

	if (!opt.v)
		printf("FT_PING %s (%s) %d data bytes\n", target, inet_ntoa(addr->sin_addr), opt.s - 8);
	else
	{

		int pid = getpid();
		int hexaCheck = pid < 16 ? 1 : 0;
		printf("FT_PING %s (%s) %d data bytes, id 0x00%s%x = %i\n", target, inet_ntoa(addr->sin_addr), opt.s - 8, (hexaCheck ? "0" : ""), pid, pid);
	}

	char my_ip[INET_ADDRSTRLEN];
	const char *interface = "eth0";

	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
	{
		perror("socket");
		close(sockfd);
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0)
	{
		perror("ioctl");
		close(fd);
		close(sockfd);
		return -1;
	}

	close(fd);

	struct sockaddr_in *my_addr = (struct sockaddr_in *)&ifr.ifr_addr;
	strcpy(my_ip, inet_ntoa(my_addr->sin_addr));

	struct in_addr source = {inet_addr(my_ip)};
	struct in_addr dest = {inet_addr(inet_ntoa(addr->sin_addr))};

	struct in_addr subnet_mask = {inet_addr("255.255.255.0")};

	uint32_t source_net = ntohl(source.s_addr) & ntohl(subnet_mask.s_addr);
	uint32_t dest_net = ntohl(dest.s_addr) & ntohl(subnet_mask.s_addr);

	int same_subnet = false;
	if (source_net != dest_net && strcmp(inet_ntoa(addr->sin_addr), "127.0.0.1") != 0)
	{
		close(fd);
		if (opt.r)
		{
			fprintf(stderr, "ft_ping: sending packet: Network is unreachable\n");
			close(sockfd);
			exit(1);
		}
	} else {
		same_subnet = true;
	}

	while (--opt.l >= 0)
	{
		char req[opt.s];
		build_request(req, seq, sizeof(req));
		struct timeval start;
		struct timeval end;
		// Send ICMP packet
		gettimeofday(&start, NULL);
		int code = sendto(sockfd, req, opt.s, 0, (struct sockaddr *)addr, sizeof(struct sockaddr));

		if (code >= 0)
		{
			transmitted++;
		}
		// Receive ICMP packet
		char recv_buf[opt.s * 2];
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
		int recv_len = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&sender_addr, &sender_addr_len);
		// int recv_len = recvmsg(sockfd, &msg, 0);

		if (recv_len >= 0)
		{
			received++;
		}
		gettimeofday(&end, NULL);
		struct iphdr *ip = (struct iphdr *)recv_buf;
		struct icmphdr *icmp = (struct icmphdr *)(recv_buf + (ip->ihl << 2));

		unsigned char ttl = ip->ttl;
		struct timeval *recv_time = (struct timeval *)(recv_buf + 8);
		long secs_diff = end.tv_sec - start.tv_sec;
		long usecs_diff = end.tv_usec - start.tv_usec;

		if (usecs_diff < 0)
		{
			// Adjust for the fact that usecs_diff is negative
			--secs_diff;
			usecs_diff += 1000000; // Add one second in microseconds
		}

		double process_time = (double)secs_diff * 1000.0 + (double)usecs_diff / 1000.0;
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
			printf("%d bytes from %s (%s): icmp_seq=%d ttl=%u time=%.3f ms\n",
				   recv_len, argv[1], inet_ntoa(sender_addr.sin_addr), seq,
				   ttl, process_time);
		}
		else
		{
			printf("%d bytes from %s: icmp_seq=%d ttl=%u time=%.3f ms\n",
				   recv_len, inet_ntoa(sender_addr.sin_addr), seq,
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
		seq++;
	}
	while (1)
	{
		char req[opt.s];

		build_request(req, seq, sizeof(req));

		struct timeval start;
		struct timeval end;
		// Send ICMP packet
		gettimeofday(&start, NULL);

		ssize_t code = sendto(sockfd, req, sizeof(req), 0, (struct sockaddr *)addr, sizeof(struct sockaddr));

		if (code >= 0)
		{
			transmitted++;
		}
		if (opt.f)
		{
			fflush(stdout);
			printf(".");
		}
		// Receive ICMP packet
		char recv_buf[128];

		struct sockaddr_in sender_addr;
		socklen_t sender_addr_len = sizeof(sender_addr);

		long recv_len = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&sender_addr, &sender_addr_len);

		if (opt.f)
		{
			fflush(stdout);
			printf("\b");
		}
		gettimeofday(&end, NULL);
		struct iphdr *ip = (struct iphdr *)recv_buf;
		struct icmphdr *icmp = (struct icmphdr *)(recv_buf + (ip->ihl << 2));

		struct icmphdr *icmp_hdr = (void *)((uint8_t *)ip + sizeof(struct iphdr));

		char from_addr[INET_ADDRSTRLEN] = {};


		inet_ntop(AF_INET, &ip->saddr, from_addr, INET_ADDRSTRLEN);

		uint8_t icmp_type = icmp_hdr->type;
		uint8_t icmp_code = icmp_hdr->code;
		
		uint8_t ttl = ip->ttl;
		struct timeval *recv_time = (struct timeval *)(recv_buf + 8);
		long secs_diff = end.tv_sec - start.tv_sec;
		long usecs_diff = end.tv_usec - start.tv_usec;

		if (usecs_diff < 0)
		{
			// Adjust for the fact that usecs_diff is negative
			--secs_diff;
			usecs_diff += 1000000; // Add one second in microseconds
		}

		double process_time = (double)secs_diff * 1000.0 + (double)usecs_diff / 1000.0;
		if (min > process_time)
			min = process_time;
		if (max < process_time)
			max = process_time;

		if (received)
		{
			avg = ((avg * (received - 1)) + process_time) / (received);
			sum_of_squares = ((sum_of_squares * (received - 1)) + process_time * process_time) / received;
		}
		if (received > 1)
		{
			mdev = sqrt(sum_of_squares - avg * avg);
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

		if (recv_len < 0) {
			icmp_type = ICMP_DEST_UNREACH;
		}
		if (icmp_type == ICMP_ECHOREPLY || same_subnet)
		{
			received++;
		}
		if (icmp_type != ICMP_ECHOREPLY && !same_subnet)
		{
			long long int recvbytes = (recv_len) > 0 ? (recv_len - IP_HDR_SIZE) : 0;
			printf("%ld bytes from %s: %s\n", recvbytes, from_addr, icmp_error_to_string(icmp_type, icmp_code));
			if (opt.v)
			{

				uint8_t *cast_buf = (uint8_t *)icmp;

				struct iphdr *ipskip = (void *)((uint8_t *)((struct icmphdr *)recv_buf) + ICMP_HDR_SIZE);
				struct icmphdr *icmpskip;

				cast_buf += ICMP_HDR_SIZE + IP_HDR_SIZE;
				icmpskip = (struct icmphdr *)cast_buf;

				uint8_t *bytes = (uint8_t *)ipskip;
				char str[INET_ADDRSTRLEN];

				printf("IP Hdr Dump:\n");
				for (size_t i = 0; i < sizeof(struct iphdr); i += 2)
				{
					printf(" %02x%02x", *bytes, *(bytes + 1));
					bytes += 2;
				}
				printf("\nVr HL TOS  Len   ID Flg  off TTL Pro  cks      Src	"
					   "Dst	Data\n");
				printf(" %x  %x  %02x %04x %04x   %x %04x  %02x  %02x %04x ",
					   ipskip->version, ipskip->ihl, ipskip->tos, ntohs(ipskip->tot_len),
					   ntohs(ipskip->id), ntohs(ipskip->frag_off) >> 13,
					   ntohs(ipskip->frag_off) & 0x1FFF, ipskip->ttl, ipskip->protocol,
					   ntohs(ipskip->check));
				inet_ntop(AF_INET, &ipskip->saddr, str, sizeof(str));
				printf("%s  ", str);
				inet_ntop(AF_INET, &ipskip->daddr, str, sizeof(str));
				printf("%s\n", str);
				printf("ICMP: type %x, code %x, size %zu, id %#04x, seq 0x%04x\n",
					   icmp_type, icmp_code, opt.s + sizeof(*icmpskip),
					   icmpskip->un.echo.id, icmpskip->un.echo.sequence);
			}
		}
		else if (!opt.f)
		{

			if (!opt.n)
			{
				if (opt.s - ICMP_HDR_SIZE < 16)
					printf("%ld bytes from %s (%s): icmp_seq=%d ttl=%u\n", recv_len - IP_HDR_SIZE, argv[1], inet_ntoa(sender_addr.sin_addr), seq, ttl);
				else
					printf("%ld bytes from %s (%s): icmp_seq=%d ttl=%u time=%.3f ms\n", recv_len - IP_HDR_SIZE, argv[1], inet_ntoa(sender_addr.sin_addr), seq, ttl, process_time);

			}
			else
			{
				if (opt.s - ICMP_HDR_SIZE < 16)
					printf("%ld bytes from %s: icmp_seq=%d ttl=%u\n", recv_len - IP_HDR_SIZE, inet_ntoa(sender_addr.sin_addr), seq, ttl);
				else
					printf("%ld bytes from %s: icmp_seq=%d ttl=%u time=%.3f ms\n", recv_len - IP_HDR_SIZE, inet_ntoa(sender_addr.sin_addr), seq, ttl, process_time);
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
		if (icmp->type == ICMP_ECHOREPLY)
			usleep(opt.i * 1000000); // Delay between pings
		else
			usleep(1000000); // usleep for 1 second
		seq++;
	}

	freeaddrinfo(res);
	close(sockfd);

	return 0;
}