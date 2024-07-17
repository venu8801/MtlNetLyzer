
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>
#include <netinet/icmp6.h>
#include "MtlPktLyzer.h"
#include "func_dec.h"
#include "logger.h"
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) 
{
    pthread_mutex_lock(&mutex);
    while (isQueueFull()) 
    {
        pthread_cond_wait(&cond, &mutex);
    }
    enqueuePacket(pkthdr, packet);
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&mutex);
}

void processPacket(struct PacketNode packet) 
{
    struct ether_header *eth_hdr = (struct ether_header *)packet.packet;
    /* Convert timeval to human-readable format*/
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec = packet.header.ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

    /* Check Ethernet type to determine IP version*/
    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) 
    
    {
        struct ip *ip_hdr = (struct ip *)(packet.packet + sizeof(struct ether_header));

        /* Check protocol inside IP header*/
        if (ip_hdr->ip_p == IPPROTO_UDP) 
        {
            struct udphdr *udp_hdr = (struct udphdr *)(packet.packet + sizeof(struct ether_header) + sizeof(struct ip));

            /*Check source and destination ports to identify UDP packets*/
            uint16_t src_port = ntohs(udp_hdr->source);
            uint16_t dst_port = ntohs(udp_hdr->dest);
	      /* Print UDP packet details*/
            log_printf(logfile, "%s.%06ld IP %s.%u > %s.%u: UDP, length %d\n",
                       timestr,
                       (long)packet.header.ts.tv_usec,
                       inet_ntoa(ip_hdr->ip_src),
                       src_port,
                       inet_ntoa(ip_hdr->ip_dst),
                       dst_port,
                       packet.header.len);

        }
    } 
    else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) 
    {
     /* Print ARP packet details*/
        log_printf(logfile, "%s.%06ld ARP, Request who-has %s tell %s, length %d\n",
                   timestr,
                   (long)packet.header.ts.tv_usec,
                   inet_ntoa(*(struct in_addr *)(packet.packet + sizeof(struct ether_header) + 24)), // ARP source IP
                   inet_ntoa(*(struct in_addr *)(packet.packet + sizeof(struct ether_header) + 14)), // ARP target IP
                   packet.header.len);
    } 
    else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IPV6) 
    {
        struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)(packet.packet + sizeof(struct ether_header));

        /* Check next header field to determine protocol*/
        if (ip6_hdr->ip6_nxt == IPPROTO_ICMPV6) 
        {
            struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *)(packet.packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));

            /* Check ICMPv6 type*/
            if (icmp6_hdr->icmp6_type == ICMP6_ECHO_REQUEST)
             {
               /*Print ICMPv6 echo request details*/
                log_printf(logfile, "%s.%06ld ICMP6, echo request\n",
                           timestr,
                           (long)packet.header.ts.tv_usec);  

            }
        }
    } 
    else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) 
    {
        struct ip *ip_hdr = (struct ip *)(packet.packet + sizeof(struct ether_header));

        /* Check protocol inside IP header*/
        if (ip_hdr->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_hdr = (struct udphdr *)(packet.packet + sizeof(struct ether_header) + sizeof(struct ip));

            /* Check source and destination ports to identify UDP packets*/
            uint16_t src_port = ntohs(udp_hdr->source);
            uint16_t dst_port = ntohs(udp_hdr->dest);
		/* Print UDP packet details*/
            log_printf(logfile, "%s.%06ld IP %s.%u > %s.%u: UDP, length %d\n",
                       timestr,
                       (long)packet.header.ts.tv_usec,
                       inet_ntoa(ip_hdr->ip_src),
                       src_port,
                       inet_ntoa(ip_hdr->ip_dst),
                       dst_port,
                       packet.header.len);
         
        } 
        else if (ip_hdr->ip_p == IPPROTO_ICMP) 
        {
             /* Print ICMP packet details*/
            log_printf(logfile, "%s.%06ld IP %s > %s: ICMP, length %d\n",
                       timestr,
                       (long)packet.header.ts.tv_usec,
                       inet_ntoa(ip_hdr->ip_src),
                       inet_ntoa(ip_hdr->ip_dst),
                       packet.header.len);
        }
    }
}

void packet_parse_thread(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
 {
    while (1) 
    {
        pthread_mutex_lock(&mutex);
        while (isQueueEmpty()) 
        {
            pthread_cond_wait(&cond, &mutex);
        }
        struct PacketNode packet = dequeuePacket();
        pthread_cond_signal(&cond);
        pthread_mutex_unlock(&mutex);

        /* Process the packet here*/
        processPacket(packet);
    }
    pthread_exit(NULL);
}

void packet_capture_thread(void *arg) 
{
    log_printf(logfile,"enter into capture_thread");
	pcap_t *handle = (pcap_t *)arg;
	pcap_loop(handle, -1, packet_handler, NULL);
	pthread_exit(NULL);
}

u_int8_t capture_thread_implement(char *filter, char *interface, pcap_t *handle, struct fptr *gfptr) 
{
    struct bpf_program fp;

    /* Further processing based on options*/
    initPacketQueue();
	
    log_printf(logfile,"Interface: %s, Filter: %s\n", interface, filter);
    log_printf(logfile,"Capturing from Interface: %s\n", interface);
    
    pthread_t capture_thread, parse_thread;
    log_printf(logfile,"thread creation in process");
    if (pthread_create(&capture_thread, NULL, (void* (*)(void*))gfptr->bfill_fptr, (void *)handle) != 0 ||
        pthread_create(&parse_thread, NULL, (void* (*)(void*))gfptr->bparse_fptr, (void *)handle) != 0) 
        {
        fprintf(stderr, "Error creating packet capture or parse thread\n");
        pcap_freecode(&fp); /* Free the compiled filter*/
        pcap_close(handle); /* Close pcap handle*/
        pthread_mutex_destroy(&mutex);
        pthread_cond_destroy(&cond);
        return EXIT_FAILURE;
    }

    /* Wait for the packet capture thread to finish*/
    pthread_join(capture_thread, NULL);
    pthread_join(parse_thread, NULL);

    /* Cleanup*/
    pcap_freecode(&fp); /* Free the compiled filter*/
    pcap_close(handle); /* Close pcap handle*/
    pthread_mutex_destroy(&mutex);
    pthread_cond_destroy(&cond);
    return EXIT_SUCCESS;
}
