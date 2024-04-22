#include "./helper_func.h"

/* Function to reply to ICMP echo requests */
void reply_icmp(char *buf,
                struct ether_header *etherhdr, struct iphdr *ip_hdr,
                struct icmphdr *icmp_hdr, int interface, int len) {


    char *new_buf = malloc(MAX_PACKET_LEN);
    memset(new_buf, 0, MAX_PACKET_LEN);
    
    // swap mac adresses 
    struct ether_header *new_etherhdr = (struct ether_header *)new_buf;
    memcpy(new_etherhdr->ether_dhost, etherhdr->ether_shost, 6);
    memcpy(new_etherhdr->ether_shost, new_etherhdr->ether_dhost, 6);
    new_etherhdr->ether_type = htons(ETHERTYPE_IP);
    
    struct iphdr *new_iphdr = (struct iphdr *)(new_buf + sizeof(struct ether_header));
    memcpy(new_iphdr, ip_hdr, sizeof(struct iphdr));
    //swap ip addreses
    new_iphdr->daddr = ip_hdr->saddr;
    new_iphdr->saddr = ip_hdr->daddr;
    new_iphdr->check = 0;
    new_iphdr->check = htons(checksum((uint16_t *)new_iphdr, sizeof(struct iphdr)));

    struct icmphdr *new_icmp_hdr = (struct icmphdr *)(new_buf + sizeof(struct ether_header) + sizeof(struct iphdr));
    memcpy(new_icmp_hdr, icmp_hdr, sizeof(struct icmphdr));
    new_icmp_hdr->type = 0;
    new_icmp_hdr->checksum = 0;
    new_icmp_hdr->checksum = htons(checksum((uint16_t *)new_icmp_hdr, sizeof(struct icmphdr)));

    // constructing the packet
    memcpy(new_buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr),
            buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), 
            MAX_PACKET_LEN - (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr)));
    
    send_to_link(interface, new_buf, len);
}

/* Function to reply to ICMP messages for unreachable destinations or TTL exceeded */
void tle_unrch_reply_icmp(char *buf,
                struct ether_header *etherhdr, struct iphdr *ip_hdr,
                struct icmphdr *icmp_hdr, int interface, int len, uint8_t type) {

    char *new_buf = malloc(MAX_PACKET_LEN);
    memset(new_buf, 0, MAX_PACKET_LEN);

    struct ether_header *new_etherhdr = (struct ether_header *)new_buf;
    memcpy(new_etherhdr->ether_dhost, etherhdr->ether_shost, 6);
    memcpy(new_etherhdr->ether_shost, etherhdr->ether_dhost, 6);
    new_etherhdr->ether_type = htons(ETHERTYPE_IP);
    
    struct iphdr *new_iphdr = (struct iphdr *)(new_buf + sizeof(struct ether_header));
   
    new_iphdr->daddr = ip_hdr->saddr;
    new_iphdr->saddr = ip_hdr->daddr;
    new_iphdr->tot_len = sizeof(struct icmphdr) + sizeof(struct iphdr);
    new_iphdr->tot_len = htons(new_iphdr->tot_len);
    new_iphdr->check = 0;
    new_iphdr->ttl = 64;
    new_iphdr->ihl = 5;
    new_iphdr->version = 4;
    new_iphdr->frag_off = 0;
    new_iphdr->id = htons(1);
    new_iphdr->tos = 0;
    new_iphdr->protocol = 1;
    new_iphdr->check = htons(checksum((uint16_t *)new_iphdr, sizeof(struct iphdr)));



    struct icmphdr *new_icmp_hdr = (struct icmphdr *)(new_buf + sizeof(struct ether_header) + sizeof(struct iphdr));
    memcpy(new_icmp_hdr, icmp_hdr, sizeof(struct icmphdr));
    new_icmp_hdr->type = type;
    new_icmp_hdr->checksum = 0;
    new_icmp_hdr->checksum = htons(checksum((uint16_t *)new_icmp_hdr, sizeof(struct icmphdr)));
    
    memcpy(new_buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr),
            buf + sizeof(struct ether_header), 
            sizeof(struct iphdr) + 8);
    
    send_to_link(interface, new_buf, 8 + sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr));
}

/*
 Returns a pointer (eg. &rtable[i]) to the best matching route, or NULL if there
 is no matching route.
*/
struct route_table_entry *get_best_route(uint32_t ip_dest, uint16_t rtable_len,
                                         struct route_table_entry *rtable) {
        int left = 0, right = rtable_len - 1;
        struct route_table_entry *sol = NULL;
        while (left <= right) {
                printf("%d %d\n", left, right);
                int mid = (left + right) / 2;
                if (rtable[mid].prefix == (ip_dest & rtable[mid].mask)) {
                        sol = &rtable[mid];
                        left = mid + 1;

                } else if (ntohl(rtable[mid].prefix) < ntohl((ip_dest & rtable[mid].mask))) 
                        left = mid + 1;
                else 
                        right = mid - 1;
                
        }
        
        return sol;
}


void arp_request(struct route_table_entry *best_route) {
        char *new_buf = malloc(MAX_PACKET_LEN);
        memset(new_buf, 0, MAX_PACKET_LEN);

        struct ether_header *new_etherhdr = (struct ether_header *)new_buf;
        get_interface_mac(best_route->interface, new_etherhdr->ether_shost);
        memset(new_etherhdr->ether_dhost, 0xff, 6);
        new_etherhdr->ether_type = htons(ETHERTYPE_ARP);

        struct arp_header *new_arp_hdr = (struct arp_header *)(new_buf + sizeof(struct ether_header));
        new_arp_hdr->htype = htons(1);
        new_arp_hdr->hlen = 6;
        new_arp_hdr->ptype = htons(ETHERTYPE_IP);
        new_arp_hdr->plen = 4;
        new_arp_hdr->op = htons(1);
        get_interface_mac(best_route->interface, new_arp_hdr->sha);
        new_arp_hdr->spa = inet_addr(get_interface_ip(best_route->interface));
        new_arp_hdr->tpa = best_route->next_hop;
        memset(new_arp_hdr->tha, 0xff, 6);

        
        send_to_link(best_route->interface, new_buf,sizeof(struct ether_header) + sizeof(struct arp_header));
}

void arp_reply(struct arp_header *arp_hdr, int interface, char *buf, int len, struct ether_header *eth_hdr) {
    uint8_t mac[6];
    uint8_t aux[6];
    uint32_t new_aux;
    // swaping dest and source to be able
    // to send back the reply
    new_aux = arp_hdr->tpa;
    arp_hdr->tpa = arp_hdr->spa;
    arp_hdr->spa = new_aux;

    memcpy(aux, eth_hdr->ether_dhost, 6);
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
    memcpy(eth_hdr->ether_shost, aux, 6);
    get_interface_mac(interface, eth_hdr->ether_shost);

    memcpy(arp_hdr->tha, arp_hdr->sha, 6);
    get_interface_mac(interface, mac);
    memcpy(arp_hdr->sha, mac, 6);
    
    // changing from request to reply
    arp_hdr->op = htons(2);
    send_to_link(interface, buf, len);
}