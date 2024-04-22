#include "queue.h"
#include "lib.h"
#include <string.h>
#include "helper_func.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* arp table */
struct arp_table_entry *arp_table;
int arp_table_len;

struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
	/*  Iterate through the MAC table and search for an entry
	 * that matches given_ip. */
	/* We can iterate thrpigh the mac_table for (int i = 0; i <
	 * mac_table_len; i++) */

	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == given_ip)
			return &arp_table[i];
	}
	return NULL;
}

// compare functon used for qsort
int compare_rtable_entr(const void *lhs, const void *rhs) {
	struct route_table_entry lhs_entry = *(struct route_table_entry *)lhs;
	struct route_table_entry rhs_entry = *(struct route_table_entry *)rhs;

	if (ntohl(lhs_entry.mask) > ntohl(rhs_entry.mask))
		return 1;
	if (lhs_entry.mask == rhs_entry.mask)
		return ntohl(lhs_entry.prefix) > ntohl(rhs_entry.prefix);

	return -1;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	

	/* Code to allocate the MAC and route tables */
	rtable = malloc(sizeof(struct route_table_entry) * 70000);
	/* DIE is a macro for sanity checks */
	DIE(rtable == NULL, "memory");

	arp_table = malloc(sizeof(struct  arp_table_entry) * 100);
	DIE(arp_table == NULL, "memory");
	
	/* Read the static routing table and the MAC table */
	rtable_len = read_rtable(argv[1], rtable);
	// arp_table_len = parse_arp_table("arp_table.txt", arp_table);
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare_rtable_entr);

	struct queue *my_queue = queue_create();

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
		printf("tip ether %X\n", ntohs(eth_hdr->ether_type));
		/* Check if we got an IPv4 packet */
		if (eth_hdr->ether_type == htons(ETHERTYPE_IP)) {
			// printf("%d\n", ip_hdr->ttl);

			// verify if checksum failed
			uint16_t old_sum = ip_hdr->check;
			ip_hdr->check = 0;
			if (old_sum != htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)))) {
				printf("Checksum failed\n");
				continue;
			}

			if (inet_addr(get_interface_ip(interface)) == ip_hdr->daddr) {
				struct icmphdr *icmp = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
				//echo_reply;
				reply_icmp(buf, eth_hdr, ip_hdr, icmp, interface, len);
			} else {
				
				struct icmphdr *icmp = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
				ip_hdr->ttl--;
				if (ip_hdr->ttl == 0) {
					printf("ajung in tle\n");
					tle_unrch_reply_icmp(buf, eth_hdr, ip_hdr, icmp, interface, len, 11);
				} else {
					printf("ajung in icmp dupa tle\n");
					ip_hdr->check = 0;
					ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

			/* Call get_best_route to find the most specific route, continue; (drop) if null */
					struct route_table_entry *best_route =  get_best_route(ip_hdr->daddr, rtable_len, rtable);
					printf("ruta cea mai buna %p\n", best_route);
					if (best_route == NULL) {
						struct icmphdr *icmp = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
						//dest_unknown
						tle_unrch_reply_icmp(buf, eth_hdr, ip_hdr, icmp, interface, len, 3);
						printf("no route\n");
						continue;
					} else {

				/* Update the ethernet addresses. Use get_mac_entry to find the destination MAC
				* address. Use get_interface_mac(m.interface, uint8_t *mac) to
				* find the mac address of our interface. */
						printf("am ajuns la trimitere\n");
						if (get_arp_entry(best_route->next_hop) == NULL) {
							arp_request(best_route);
							struct packet *my_pckt = malloc(sizeof(struct packet));
							my_pckt->buffer = malloc(MAX_PACKET_LEN);
							my_pckt->interface = interface;
							my_pckt->length = len;
							memcpy(my_pckt->buffer, buf, len);
							queue_enq(my_queue, my_pckt);

							printf("adresa ip cand dau request : %d\n", best_route->next_hop);

						} else {
							memcpy(eth_hdr->ether_dhost, get_arp_entry(best_route->next_hop)->mac, 6);
							get_interface_mac(best_route->interface, eth_hdr->ether_shost);
							send_to_link(best_route->interface, buf, len);
						}
					}
			 	}
			}
		} else if (eth_hdr->ether_type == htons(ETHERTYPE_ARP)) {
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
			// printf("huh? %d\n");
			if (arp_hdr->op == htons(1)) {
				printf("am primit arp request\n");
				arp_reply(arp_hdr, interface, buf, len, eth_hdr);
			} 
			else if (arp_hdr->op == htons(2)) {
				/*
				Extracting the source hardware address (SHA) and source protocol address (SPA), 
				which essentially is the response to our earlier query - "What MAC address does
				 this IP address have?" 
				Initially, it was the target protocol address (TPA), but in the response, 
				there's a swap between the sender and target.
				Creating a new entry in the ARP table with these extracted fields.
				Dequeue packets from the packet queue and check those packets whose 'next hop'
				 matches the newly added entry in the ARP table.
				*/
				printf("primit arp reply, dam send la packet\n");

				struct arp_table_entry *new_arp_table_entry = malloc(sizeof(struct arp_table_entry) * 100);
				new_arp_table_entry->ip = arp_hdr->spa;
				memcpy(new_arp_table_entry->mac, arp_hdr->sha, 6);
				memcpy(&arp_table[arp_table_len++], new_arp_table_entry, sizeof(struct arp_table_entry));
				queue new_queue = queue_create();
				printf("adresa ip cand primesc reply : %d\n", new_arp_table_entry->ip);

				
				while (!queue_empty(my_queue)) {
					struct packet *curr_packet = queue_deq(my_queue);
					uint32_t dest_ip = ((struct iphdr *)(curr_packet->buffer + sizeof(struct ether_header)))->daddr;
					struct route_table_entry *best_route =  get_best_route(dest_ip, rtable_len, rtable);
					if (best_route->next_hop == new_arp_table_entry->ip) {
						send_to_link(best_route->interface, curr_packet->buffer, curr_packet->length);
					} else {
						queue_enq(new_queue, curr_packet);
					}
				}
				my_queue = new_queue;
			}		
		}
	}	
}


