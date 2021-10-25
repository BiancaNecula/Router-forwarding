#include <queue.h>
#include "skel.h"

struct arp_entry {
	uint32_t ip_addr;
	uint8_t mac_addr[6];
};

struct rout_entry {
	uint32_t prefix;
	uint32_t nexthop;
	uint32_t mask;
	int interface;
};


long long binary_search(struct rout_entry *routing_table, uint32_t ipaddr, uint32_t mask, long long start, long long end){
	long long mij = (start + end) / 2;
	if ((ipaddr & routing_table[mij].mask) == routing_table[mij].prefix) {
		if ((ipaddr & routing_table[mij].mask) != routing_table[mij-1].prefix) {
			return mij;
		}  
		else if (mask < routing_table[mij].mask) {
			mask =  routing_table[mij].mask;
			return binary_search(routing_table,  ipaddr, mask, start, mij-1);
		}
		else if (mask == routing_table[mij].mask) {
			return mij;
		}
	}
	if (end < start) {
		return -1;
	}
	if ((ipaddr & routing_table[mij].mask) > routing_table[mij].prefix) {
		return binary_search(routing_table, ipaddr, mask, mij+1, end);
	}
	if ((ipaddr & routing_table[mij].mask) < routing_table[mij].prefix) {
                return binary_search(routing_table, ipaddr, mask, start, mij-1);
        }

	return -1;
}

void send_arp(uint32_t daddr, uint32_t saddr, struct ether_header *eth_hdr, int interface, uint16_t arpop)
{
	struct arp_header arp_hdr;
	packet packet;

	arp_hdr.htype = htons(ARPHRD_ETHER);
	arp_hdr.ptype = htons(2048);
	arp_hdr.op = arpop;
	arp_hdr.hlen = 6;
	arp_hdr.plen = 4;
	memcpy(arp_hdr.sha, eth_hdr->ether_shost, 6);
	memcpy(arp_hdr.tha, eth_hdr->ether_dhost, 6);
	arp_hdr.spa = saddr;
	arp_hdr.tpa = daddr;
	memset(packet.payload, 0, 1600);
	memcpy(packet.payload, eth_hdr, sizeof(struct ethhdr));
	memcpy(packet.payload + sizeof(struct ethhdr), &arp_hdr, sizeof(struct arp_header));
	packet.len = sizeof(struct arp_header) + sizeof(struct ethhdr);
	send_packet(interface, &packet);
}

/*
void routing_parser(int *nr_rout_entries, int *rout_cap, char *filename) {
	FILE *file = fopen(filename, "r");
	char buf[101];
	while(fgets(buf, 100, file)) {
		struct rout_entry entry;
		char *p;
		p = strtok(buf, " ");
		char prefix[40];
		memset(prefix, 0, 40);
		memcpy(prefix, p, strlen(p));
		struct in_addr ipstr;
		inet_aton(prefix, &ipstr);
		entry.prefix = ipstr.s_addr;
		p = strtok(NULL, " ");
		char nexthop[40];
		memset(nexthop, 0, 40);
		memcpy(nexthop, p, strlen(p));
		//struct in_addr ipstr;
                inet_aton(nexthop, &ipstr);
                entry.nexthop = ipstr.s_addr;
		p = strtok(NULL, " ");
                char mask[40];
		memset(mask, 0, 40);
                memcpy(mask, p, strlen(p));
		//struct in_addr ipstr;
                inet_aton(mask, &ipstr);
                entry.mask = ipstr.s_addr;
		p = strtok(NULL, " ");
                char interface[40];
		memset(interface, 0, 40);
                memcpy(interface, p, strlen(p));
		entry.interface = atoi(interface);
		//put(routing_table, prefix, strlen(prefix) + 1, &entry);
		if((*rout_cap) == (*nr_rout_entries)) {
                	(*rout_cap)++;
                        routing_table = realloc(routing_table, sizeof(struct rout_entry)*(*rout_cap));
                }
		(*nr_rout_entries)++;
		memcpy(&routing_table[(*nr_rout_entries)], &entry, sizeof(struct rout_entry));
		//printf("%d\n" ,routing_table[(*nr_rout_entries)].prefix);

	}
	fclose(file);

}


*/
void send_myicmp(packet* m, int type) {
	struct ether_header *eth_r = (struct ether_header *)malloc(sizeof(struct ether_header));
	struct iphdr *iph_r = (struct iphdr *)malloc(sizeof(struct iphdr));
	struct icmphdr *icmph_r = (struct icmphdr *)malloc(sizeof(struct icmphdr));
	struct ether_header *eth = (struct ether_header *)m->payload;
	memcpy(eth_r->ether_shost, eth->ether_dhost, sizeof(eth_r->ether_shost));
	memcpy(eth_r->ether_dhost, eth->ether_shost, sizeof(eth_r->ether_dhost));
	eth_r->ether_type = htons(ETHERTYPE_IP);
	struct iphdr *iph = (struct iphdr *)(m->payload + (sizeof(struct ether_header))); 
	iph_r->version = iph->version;
	iph_r->ihl = iph->ihl;
	iph_r->tos = iph->tos;
	iph_r->tot_len = htons(iph->tot_len); 
	iph_r->id = htons(iph->id);
	iph_r->frag_off = htons(iph->frag_off);
	iph_r->ttl = iph->ttl;
	iph_r->protocol = 1;
	struct in_addr ipstr;
        inet_aton(get_interface_ip(m->interface), &ipstr);
	iph_r->saddr = htonl(ipstr.s_addr);
	iph_r->daddr = htonl(iph->saddr);
	iph_r->check = 0;
	iph_r->check = ip_checksum(iph_r, sizeof(struct iphdr));  // TODO: de calculat checksum
	struct icmphdr *icmph = (struct icmphdr *)(m->payload + (sizeof(struct ether_header) + sizeof(struct iphdr)));
	icmph_r->code = icmph->code;
	icmph_r->type = type;
	icmph_r->un.echo.id = icmph->un.echo.id;
	icmph_r->un.echo.sequence = icmph->un.echo.sequence;
	icmph_r->checksum = 0;
	icmph_r->checksum = ip_checksum(icmph_r, sizeof(struct icmphdr));  // TODO: de calculat checksum
	packet r;
	memcpy(r.payload, eth_r, sizeof(*eth_r));
	memcpy(r.payload + sizeof(*eth_r), iph_r, sizeof(*iph_r));
	memcpy(r.payload + sizeof(*eth_r) + sizeof(*iph_r), icmph_r, sizeof(*icmph_r));
	r.len = sizeof(*eth_r) + sizeof(*iph_r) + sizeof(*icmph_r);
	r.interface = m->interface;
	send_packet(r.interface, &r);
}

void send_myarp(packet* m) {
	packet r;
	struct ether_header *eth = (struct ether_header *)m->payload;
	struct arp_header *arph = (struct arp_header *)(m->payload + (sizeof(struct ether_header)));
	struct ether_header *eth_r = (struct ether_header *)malloc(sizeof(struct ether_header));
        struct arp_header *arph_r = (struct arp_header *)malloc(sizeof(struct arp_header));
	uint8_t mac[6];
        get_interface_mac(m->interface, mac);
	memcpy(eth_r->ether_dhost, eth->ether_shost, sizeof(eth_r->ether_dhost));	
	memcpy(eth_r->ether_shost, mac, sizeof(eth_r->ether_shost));
        eth_r->ether_type = htons(ETHERTYPE_ARP);
	arph_r->htype = htons(arph->htype);
	arph_r->ptype = htons(arph->ptype);
	arph_r->hlen = 6;
	arph_r->plen = 4;
	arph_r->op = htons(2);
	arph_r->tpa = arph->spa;
	arph_r->spa = arph->tpa;
	for(int i = 0; i<6; i++) {
		arph_r->sha[i] = mac[i];
		arph_r->tha[i] = eth->ether_shost[i];
	}
	r.len = sizeof(*eth_r) + sizeof(*arph_r);
        r.interface = m->interface;
	memcpy(r.payload, eth_r, sizeof(*eth_r));
        memcpy(r.payload + sizeof(*eth_r), arph_r, sizeof(*arph_r));
	send_packet(r.interface, &r);
}

int rout_comparator(const void *v1, const void *v2)
{
    const struct rout_entry *p1 = (struct rout_entry *)v1;
    const struct rout_entry *p2 = (struct rout_entry *)v2;
    if (p1->prefix < p2->prefix) {
        return -1;
    }
    else if (p1->prefix > p2->prefix) {
        return 1;
    }
    else {
	if (p1->mask < p2->mask) {
        	return 1;
    	}
    	else if (p1->mask > p2->mask) {
        	return -1;
    	}
        return 0;
    }
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;
	init(argc - 2, argv + 2);


	struct rout_entry *routing_table = (struct rout_entry *)calloc(100000, sizeof(struct rout_entry));
	long long nr_rout_entries = 0;
	long long rout_cap = 100000;
	struct arp_entry *arp_entries = (struct arp_entry *)malloc(sizeof(struct arp_entry) * 100);
	int nr_arp_entries = 0;
	int arp_cap = 100;


	FILE *file = fopen(argv[1], "r");
        char buf[101];
        while(fgets(buf, 100, file)) {
                char *p;
                p = strtok(buf, " ");
                char prefix[40];
                memset(prefix, 0, 40);
                memcpy(prefix, p, strlen(p));
                struct in_addr ipstr;
                inet_aton(prefix, &ipstr);
                routing_table[nr_rout_entries].prefix = ipstr.s_addr;
		p = strtok(NULL, " ");
                char nexthop[40];
                memset(nexthop, 0, 40);
                memcpy(nexthop, p, strlen(p));
                inet_aton(nexthop, &ipstr);
                routing_table[nr_rout_entries].nexthop = ipstr.s_addr;
		p = strtok(NULL, " ");
                char mask[40];
                memset(mask, 0, 40);
                memcpy(mask, p, strlen(p));
                inet_aton(mask, &ipstr);
                routing_table[nr_rout_entries].mask = ipstr.s_addr;
		p = strtok(NULL, " ");
                char interface[40];
                memset(interface, 0, 40);
                memcpy(interface, p, strlen(p));
		int aux = atoi(interface);
		routing_table[nr_rout_entries].interface = aux;
		//printf("%d\n" ,routing_table[nr_rout_entries].prefix);
		nr_rout_entries++;
		if(rout_cap == nr_rout_entries) {
                        rout_cap++;
                        routing_table = realloc(routing_table, sizeof(struct rout_entry) * rout_cap);
                }

        }
	nr_rout_entries--;
        fclose(file);

	queue qu;
	qu = queue_create();

	qsort(routing_table, nr_rout_entries, sizeof(struct rout_entry), rout_comparator);
	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		struct ether_header *eth = (struct ether_header *)m.payload;
		if (ntohs(eth->ether_type) == 0x0800) { // IPv4 
			struct iphdr *iph = (struct iphdr *)(m.payload + (sizeof(struct ether_header)));
			if (iph->protocol == 1) {
		        	struct icmphdr *icmph = (struct icmphdr *)(m.payload + (sizeof(struct ether_header) + sizeof(struct iphdr)));
				if (icmph->type == 8) { //ICMP echo request
					struct in_addr ip_addr;
					ip_addr.s_addr = iph->daddr;
					if (!strcmp(inet_ntoa(ip_addr), get_interface_ip(m.interface))) { // the packet is for router
						send_myicmp(&m, 0); // send ICMP echo reply back at source
						continue;
					}	
				}
			}

			if (iph->ttl <= 1) {
                                send_myicmp(&m, 11);
                                continue;
                        }

			uint32_t ip_daddr = iph->daddr;
                        uint32_t mask = 0;
			int index = binary_search(routing_table, ip_daddr, mask, 0, nr_rout_entries);
			if(index == -1) {
                                send_myicmp(&m, 3);
                                continue;
                        }
			struct rout_entry *found_entry = &routing_table[index];
		        
			unsigned short checksum = iph->check;
			iph->check = 0;
			if (checksum != ip_checksum(iph, sizeof(struct iphdr))) {
				continue;
			}
			iph->ttl--;
		        iph->check = ip_checksum(iph, sizeof(struct iphdr));	
                        uint32_t next_ip = found_entry->nexthop;
			int found_arp = 0;
			if (nr_arp_entries != 0) {
                        	for(int i = 0; i<nr_arp_entries; i++) {
                        		if(arp_entries[i].ip_addr == next_ip) {
						found_arp = 1;
						memcpy(eth->ether_dhost, arp_entries[i].mac_addr, sizeof(eth->ether_dhost));
						get_interface_mac(found_entry->interface, eth->ether_shost);
                                		send_packet(found_entry->interface, &m);
                                        	break;
                                	}

                        	}
			}
			if(found_arp == 0 || nr_arp_entries == 0) {
				packet *c = malloc(sizeof(packet));
				memcpy(c, &m, sizeof(packet));
				queue_enq(qu, c);

				struct ether_header *eth_r = (struct ether_header *)malloc(sizeof(struct ether_header));
				uint8_t mac[6];
			        for(int i = 0; i<6; i++){
					mac[i] = 255;
				}
				memcpy(eth_r->ether_dhost, mac, sizeof(mac));
				get_interface_mac(found_entry->interface, eth_r->ether_shost);	
				eth_r->ether_type = htons(ETHERTYPE_ARP);
				struct in_addr ipstr;
				char *ip = get_interface_ip(found_entry->interface);
				inet_aton(ip, &ipstr);
				send_arp(found_entry->nexthop, ipstr.s_addr, eth_r, found_entry->interface, htons(1));
				continue;

			}
		}
		else if (ntohs(eth->ether_type) == 0x0806) { // ARP 
		       struct arp_header *arph = (struct arp_header *)(m.payload + (sizeof(struct ether_header)));
		       if (ntohs(arph->op) == 1) { // ARP request
				// TODO: de verificat daca pachetul este pt acest router
				struct ether_header *eth_r = (struct ether_header *)malloc(sizeof(struct ether_header));
				uint8_t mac[6];
			        get_interface_mac(m.interface, mac);
        			memcpy(eth_r->ether_dhost, eth->ether_shost, sizeof(eth_r->ether_dhost));
        			memcpy(eth_r->ether_shost, mac, sizeof(eth_r->ether_shost));
        			eth_r->ether_type = htons(ETHERTYPE_ARP);
				send_arp(arph->spa, arph->tpa, eth_r, m.interface, htons(2));
			
		       }
		       else if (ntohs(arph->op) == 2) { // ARP reply
			        if(arp_cap == nr_arp_entries) {
				       arp_cap++;
				       arp_entries = realloc(arp_entries, sizeof(struct arp_entry)*arp_cap);
				}
				struct arp_entry new_entry;
				new_entry.ip_addr = arph->spa;
				memcpy(new_entry.mac_addr, eth->ether_shost, sizeof(new_entry.mac_addr));
				arp_entries[nr_arp_entries] = new_entry;
			        nr_arp_entries++;	
				
				while(!queue_empty(qu)) {
					packet *top = malloc(sizeof(packet));
					top = queue_deq(qu);
					struct ether_header *eth_top = (struct ether_header *)top->payload;
					struct iphdr *iph_top = (struct iphdr *)(top->payload + (sizeof(struct ether_header)));
					uint32_t ip_daddr = iph_top->daddr; 
					uint32_t mask = 0;
					int index = binary_search(routing_table, ip_daddr, mask, 0, nr_rout_entries);
					struct rout_entry *found_entry = &routing_table[index];
					uint32_t next_ip = found_entry->nexthop;
					for(int i = 0; i<nr_arp_entries; i++) {
						if(arp_entries[i].ip_addr == next_ip) {
							memcpy(eth_top->ether_dhost, arp_entries[i].mac_addr, sizeof(eth_top->ether_dhost));
							memcpy(top->payload, eth_top, sizeof(*eth_top));
							send_packet(found_entry->interface, top);
							break;
						}
						
					}


				}



				
		       }
		       	       
		}

		
	}
}
