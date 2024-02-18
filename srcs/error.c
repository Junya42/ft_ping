#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <stdio.h>

char    *get_right_icmp_error(int type, int code)
{
	switch (type) 
    {
        case ICMP_DEST_UNREACH:
		switch(code) 
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
		switch(code) 
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
		switch(code) 
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