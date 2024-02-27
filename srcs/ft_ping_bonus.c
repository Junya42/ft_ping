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

char *get_right_icmp_error(int type, int code);

#define PACKET_SIZE 64
#define ICMP_HDR_SIZE 8
#define ICMP_BODY_SIZE 56

typedef struct s_icmp
{
	struct icmphdr hdr;
	char *packet;
} t_icmp;

t_icmp req;

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
	if (req.packet)
		free(req.packet);
	exit(sig);
}

struct option
{
	int f;	  // ok
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

void build_request(t_icmp *request, int seq)
{
	bzero(request, sizeof(t_icmp));

	request->hdr.type = ICMP_ECHO;
	request->hdr.code = 0;
	request->hdr.un.echo.id = getpid();
	request->hdr.un.echo.sequence = seq;
	request->hdr.checksum = 0;
	request->hdr.checksum = checksum(request, sizeof(request));
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

	int seq = 0;

	req.packet = (char *)malloc(opt.s);
	gettimeofday(&total, NULL);
	signal(SIGINT, sighandler);
	// Ping loop

	if (!opt.v)
		printf("FT_PING %s (%s) %d(%d) bytes of data.\n", target, inet_ntoa(addr->sin_addr), opt.s - 8, opt.s + 20);
	else
		printf("FT_PING %s (%s) %d(%d) bytes of data, id 0x0%x = %i.\n", target, inet_ntoa(addr->sin_addr), opt.s - 8, opt.s + 20, getpid(), getpid());
	while (--opt.l >= 0)
	{
		build_request(&req, ++seq);
		struct timeval start;
		struct timeval end;
		// Send ICMP packet
		gettimeofday(&start, NULL);
		int code = sendto(sockfd, &req, opt.s, 0, (struct sockaddr *)addr, sizeof(struct sockaddr));

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
		int recv_len = recvfrom(sockfd, recv_buf, opt.s, 0, (struct sockaddr *)&sender_addr, &sender_addr_len);
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
			printf("%d bytes from %s (%s): icmp_seq=%d ttl=%u time=%.2f ms\n",
				   recv_len, argv[1], inet_ntoa(sender_addr.sin_addr), seq,
				   ttl, process_time);
		}
		else
		{
			printf("%d bytes from %s: icmp_seq=%d ttl=%u time=%.2f ms\n",
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
	}
	while (1)
	{
		build_request(&req, ++seq);

		struct timeval start;
		struct timeval end;
		// Send ICMP packet
		gettimeofday(&start, NULL);
		int code = sendto(sockfd, &req, opt.s, 0, (struct sockaddr *)addr, sizeof(struct sockaddr));

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
		int recv_len = recvfrom(sockfd, recv_buf, opt.s, 0, (struct sockaddr *)&sender_addr, &sender_addr_len);
		// int recv_len = recvmsg(sockfd, &msg, 0);

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

		if (!opt.f)
		{

			if (!opt.n)
			{
				printf("%d bytes from %s (%s): icmp_seq=%d ", recv_len, argv[1], inet_ntoa(sender_addr.sin_addr), seq);

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
				printf("%d bytes from %s: icmp_seq=%d ", recv_len, inet_ntoa(sender_addr.sin_addr), seq);

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