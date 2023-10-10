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

#define PACKET_SIZE 64

// Structure for ICMP header
struct icmphdr {
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
    unsigned short id;
    unsigned short seq;
};

struct ipheader {
    unsigned char  ihl:4,
                   version:4;
    unsigned char  tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char  ttl;
    unsigned char  protocol;
    unsigned short check;
    unsigned int   saddr;
    unsigned int   daddr;
};



// Function to calculate the checksum for ICMP header
unsigned short checksum(void *b, int len) {
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

char *target = NULL;
unsigned long transmitted = 0;
unsigned long received = 0;
double min = __DBL_MAX__;
double avg = 0.0;
double max = __DBL_MIN__;
double sum_of_squares = 0;
double mdev = 0.0;
struct timeval total;

void	sighandler(int sig) {

	(void)sig;

	struct timeval total_end;

	gettimeofday(&total_end, NULL);
	printf("\n--- %s ping statistics ---\n", target);
	printf("%lu packets transmitted, %lu received, %ld%% packet loss, time %ld\n", 
		transmitted, received, 100 - (100 * received / transmitted),
		(unsigned long)(total_end.tv_sec - total.tv_sec) * 1000 + (unsigned long)(total_end.tv_usec - total.tv_usec) / 1000
	);
	printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", min, avg, max, mdev);
	exit(sig);
}

struct option {
	int v;
	int help;
};

void check_options(struct option *opt, char **av) {

    for (int i = 1; av[i]; i++) {

        if (av[i][0] == '-') {
            for (int j = 1; av[i][j]; j++) {

                switch (av[i][j]) {
                    
					case 'v':
						opt->v = 1;
						break;
                    case '?':
						opt->help = 1;
                        break;
					case 'h':
						opt->help = 1;
						break;
                    default:
                        // Handle unrecognized option
                        break;
                }
            }
        } else {
			if (!target)
				target = av[i];
		}
    }
}

void	help(void) {

	printf("\nUsage\n");
	printf("	ft_ping [options] <destination>\n\n");
	printf("Options:\n");
	printf("	<destination>		dns name or ip address\n");
	printf("	-v			verbose output\n");
	exit(0);
}

int main(int argc, char **argv) {
    if (argc < 2) {
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

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("Unable to create socket");
        return 1;
    }

    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt");
        return 1;
    }

    if (getaddrinfo(target, NULL, &hints, &res) != 0) {
        perror("getaddrinfo");
        return 1;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;

    int seq = 0;
    char packet[PACKET_SIZE];
    struct icmphdr *icmp = (struct icmphdr *)packet;

    icmp->type = 8;  // ICMP Echo Request
    icmp->code = 0;
    icmp->id = htons(getpid());
    icmp->checksum = 0;

	gettimeofday(&total, NULL);
	signal(SIGINT, sighandler);
    // Ping loop

	printf("FT_PING %s (%s) 56(84) bytes of data.\n", target, inet_ntoa(addr->sin_addr));
    while (1) {
        icmp->seq = htons(++seq);
		icmp->checksum = 0;
        gettimeofday((struct timeval *)(packet + 8), NULL);
        icmp->checksum = checksum(packet, PACKET_SIZE);

		struct timeval start;
		struct timeval end;
        // Send ICMP packet
		gettimeofday(&start, NULL);
        if (sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)addr, sizeof(struct sockaddr)) == -1) {
            perror("sendto");
            return 1;
        }
		transmitted++;
        // Receive ICMP packet
        char recv_buf[PACKET_SIZE];
        struct sockaddr_in sender_addr;
        socklen_t sender_addr_len = sizeof(sender_addr);
        int recv_len = recvfrom(sockfd, recv_buf, PACKET_SIZE, 0, (struct sockaddr *)&sender_addr, &sender_addr_len);

        if (recv_len < 0) {
            printf("%d\n", errno);
            perror("recvfrom");
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
		if (received > 1) {
			mdev = sqrt(sum_of_squares - avg * avg);
		}

		printf("%d bytes from %s (%s): icmp_seq=%d ttl=%u time=%.2f ms\n",
					recv_len, argv[1], inet_ntoa(sender_addr.sin_addr), ntohs(icmp->seq), 
					ttl, process_time
		);
        sleep(1);  // Delay between pings
    }

    freeaddrinfo(res);
    close(sockfd);

    return 0;
}