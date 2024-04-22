#ifndef _HELPER_FUNC_H_
#define _HELPER_FUNC_H_
#include "queue.h"
#include "protocols.h"
#include <lib.h>
#include <string.h>
#define MAX_PACKET_LEN 1600

struct packet {
    int interface;
    size_t length;
    char *buffer;
};

void tle_unrch_reply_icmp(char *buf,
                struct ether_header *etherhdr, struct iphdr *ip_hdr,
                struct icmphdr *icmp_hdr, int interface, int len, uint8_t type);

void reply_icmp(char *buf,
                struct ether_header *etherhdr, struct iphdr *ip_hdr,
                struct icmphdr *icmp_hdr, int interface, int len);

struct route_table_entry *get_best_route(uint32_t ip_dest, uint16_t rtable_len,
                                         struct route_table_entry *rtable);

void arp_reply(struct arp_header *arp_hdr, int interface, char *buf,
         int len, struct ether_header *eth_hdr);

void arp_request(struct route_table_entry *best_route);

#endif /* _HELPER_FUNC_H_ */
