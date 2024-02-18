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

// Structure for ICMP header
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

char *target = NULL;
unsigned long transmitted = 0;
unsigned long received = 0;
double min = __DBL_MAX__;
double avg = 0.0;
double max = __DBL_MIN__;
double sum_of_squares = 0;
double mdev = 0.0;
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
    printf("\n--- %s ping statistics ---\n", target);
    printf("%lu packets transmitted, %lu received, %ld%% packet loss, time %ld ms\n",
           transmitted, received, 100 - (100 * received / transmitted),
           total_time);
    printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", min, avg, max, mdev);

    if (req.packet)
        free(req.packet);
    exit(sig);
}

struct option
{
    int v;
    int help;
};

void check_options(struct option *opt, char **av)
{

    for (int i = 1; av[i]; i++)
    {

        if (av[i][0] == '-')
        {
            for (int j = 1; av[i][j]; j++)
            {

                switch (av[i][j])
                {

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
                    printf("ft_ping: invalid argument: '%s'\n", av[i] + j);
                    exit(1);
                    break;
                }
            }
        }
        else
        {
            if (!target)
            {
                target = av[i];
            }
            else
            {
                printf("ft_ping: %s: Name or service not known\n", av[i]);
                exit(2);
            }
        }
    }
}

void help(void)
{

    printf("\nUsage\n");
    printf("	ft_ping [options] <destination>\n\n");
    printf("Options:\n");
    printf("	<destination>		dns name or ip address\n");
    printf("	-v			verbose output\n");
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

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0)
    {
        perror("Unable to create socket");
        return 1;
    }

    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    /*if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        perror("setsockopt");
        return 1;
    }*/

    int ttl_value = 64;
    if (setsockopt(sockfd, SOL_IP, IP_TTL, &ttl_value, sizeof(ttl_value)) != 0)
    {
        fprintf(stderr, "Fatal error when setting the Raw Socket, Abort.\n");

        exit(1);
    }

    if (getaddrinfo(target, NULL, &hints, &res) != 0)
    {
        perror("getaddrinfo");
        return 1;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;

    int seq = 0;

    req.packet = (char *)malloc(ICMP_BODY_SIZE);
    gettimeofday(&total, NULL);
    signal(SIGINT, sighandler);
    // Ping loop

    while (1)
    {

        build_request(&req, ++seq);
        struct timeval start;
        struct timeval end;
        // Send ICMP packet
        gettimeofday(&start, NULL);

        int code = sendto(sockfd, &req, 64, 0, (struct sockaddr *)addr, sizeof(struct sockaddr));
        if (code >= 0)
        {
            transmitted++;
        }
        // Receive ICMP packet
        char recv_buf[PACKET_SIZE * 2];
        struct sockaddr_in sender_addr;
        socklen_t sender_addr_len = sizeof(sender_addr);
        int recv_len = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&sender_addr, &sender_addr_len);

        if (recv_len < 0)
        {
            printf("%d\n", errno);
            printf("recv_len = %d\n", recv_len);
            perror("recvfrom");
            return 1;
        }
        gettimeofday(&end, NULL);
        received++;
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

        unsigned short recv_checksum = icmp->checksum;
        icmp->checksum = 0;
        unsigned short calc_checksum = checksum(icmp, recv_len - (ip->ihl << 2));

        if (recv_checksum != calc_checksum)
        {
            printf("Checksum mismatch %u %u\n", recv_checksum, calc_checksum);
        }
        else if ((icmp->type != 0 && icmp->type != 8)|| icmp->code != 0)
        {
            printf("type: %d, code: %d, %s\n", icmp->type, icmp->code, get_right_icmp_error(icmp->type, icmp->code));
        }
        else
        {
            printf("%d bytes from %s (%s): icmp_seq=%d ttl=%u time=%.2f ms\n",
                   recv_len, argv[1], inet_ntoa(sender_addr.sin_addr), seq,
                   ttl, process_time);
        }
        sleep(1); // Delay between pings
    }

    freeaddrinfo(res);
    close(sockfd);

    return 0;
}