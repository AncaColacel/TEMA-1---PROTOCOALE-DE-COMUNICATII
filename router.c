#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

// declarare structura pt icmp
struct pachet_icmp
{
	struct ether_header et_hd;
	struct iphdr ip_hd;
	struct icmphdr icmp_hd;
	struct iphdr ip_vechi;
	char data[8];
} __attribute__((packed));

size_t glen;

// declarare structura pt icmp
struct icmp_reply
{
	struct ether_header et_hd;
	struct iphdr ip_hd;
	struct icmphdr icmp_hd;
	char data[1000];
} __attribute__((packed));


void ICMP(int type, int code, struct ether_header *eth_hdr, uint8_t* mac_adress, struct iphdr *ip_hdr, char* buffer, int interfata)
{
	struct pachet_icmp pachet;
	struct icmp_reply reply;
	struct icmphdr *old_icmphdr = (struct icmphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
	uint16_t tip = htons(0x800);
	uint8_t cod = 0;

	char *adr_ip_router_str = get_interface_ip(interfata);

	uint32_t adr_ip_router;
	inet_pton(AF_INET, adr_ip_router_str, &adr_ip_router);


	if(type == 0 && code == 0) {
		if (ip_hdr->daddr == adr_ip_router) {
			// completare ether_header
			memcpy(reply.et_hd.ether_shost,  mac_adress, 6);
			memcpy(reply.et_hd.ether_dhost,  eth_hdr->ether_shost, 6);
			reply.et_hd.ether_type = tip;
			// completare ip_header
			reply.ip_hd.ihl = 5;
			reply.ip_hd.version = 4;
			reply.ip_hd.tos = 0;
			reply.ip_hd.id = htons(1);
			reply.ip_hd.frag_off = 0;
			reply.ip_hd.ttl = --ip_hdr->ttl;
			reply.ip_hd.protocol = 1;
			reply.ip_hd.check = 0;
			memcpy(&reply.ip_hd.saddr, &ip_hdr->daddr, sizeof(ip_hdr->daddr));
			memcpy(&reply.ip_hd.daddr, &ip_hdr->saddr, sizeof(ip_hdr->saddr));
			// completare icmp_header
			reply.icmp_hd.type = type;
			reply.icmp_hd.code = cod;
			reply.icmp_hd.checksum = 0;
			reply.icmp_hd.un.echo.id = old_icmphdr->un.echo.id;
			reply.icmp_hd.un.echo.sequence = old_icmphdr->un.echo.sequence;
			size_t dim_send = glen - sizeof(struct ether_header) - sizeof(struct iphdr) - sizeof(struct icmphdr);
			memcpy(reply.data, buffer + sizeof (struct ether_header) + sizeof (struct iphdr) + sizeof(struct icmphdr), dim_send);
			reply.ip_hd.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + dim_send);

			uintptr_t header1 = (uintptr_t) &reply.icmp_hd;
			uintptr_t header2 = (uintptr_t) &reply.ip_hd;
			reply.icmp_hd.checksum = htons(checksum ((uint16_t *) header1, sizeof (reply.icmp_hd) + dim_send));
			reply.ip_hd.check = htons (checksum ((uint16_t *) header2, sizeof (reply.ip_hd) + sizeof (reply.icmp_hd) + dim_send));

			// transmitere mesaj ICMP
			send_to_link(interfata, (char *) &reply, sizeof (reply) - 1000 + dim_send);

			return;
		}
	}
	else if ((type == 11 && code == 0) || (type == 3 && code == 0))
	{
		// completare ether_header
		memcpy(pachet.et_hd.ether_shost,  mac_adress, 6);
		memcpy(pachet.et_hd.ether_dhost,  eth_hdr->ether_shost, 6);
		pachet.et_hd.ether_type = tip;
		// completare ip_header
		pachet.ip_hd.ihl = 5;
		pachet.ip_hd.version = 4;
		pachet.ip_hd.tos = 0;
		pachet.ip_hd.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);
		pachet.ip_hd.id = htons(1);
		pachet.ip_hd.frag_off = 0;
		pachet.ip_hd.ttl = 64;
		pachet.ip_hd.protocol = 1;
		pachet.ip_hd.check = 0;
	
		memcpy(&pachet.ip_hd.saddr, &ip_hdr->daddr, sizeof(ip_hdr->daddr));
		memcpy(&pachet.ip_hd.daddr, &ip_hdr->saddr, sizeof(ip_hdr->saddr));
		// completare icmp_header
		pachet.icmp_hd.type = type;
		pachet.icmp_hd.code = cod;
		uintptr_t header1 = (uintptr_t) &pachet.icmp_hd;
		uintptr_t header2 = (uintptr_t) &pachet.ip_hd;
		pachet.icmp_hd.checksum = 0;
		// pentru zeroizare
		pachet.icmp_hd.un.gateway = 0;
		// ip_header vechi
		uintptr_t old_struct_ip = (uintptr_t)&pachet.ip_vechi;
		memcpy((void *)old_struct_ip, ip_hdr, sizeof(pachet.ip_vechi));
		// 64 bits of Original Data Datagram
		memcpy(pachet.data, buffer + sizeof (struct ether_header) + sizeof (struct iphdr), 8);
		// transmitere mesaj ICMP

		pachet.icmp_hd.checksum = htons(checksum ((uint16_t *) header1, sizeof (pachet.icmp_hd) + sizeof (pachet.ip_vechi) + 8));
		pachet.ip_hd.check = htons (checksum ((uint16_t *) header2, sizeof (pachet.ip_hd) + sizeof (pachet.icmp_hd) + sizeof (pachet.ip_vechi) + 8));
		send_to_link(interfata, (char *) &pachet, sizeof (pachet));
	}


}

struct route_table_entry router_tbl[100000];
int rtable_len;

struct route_table_entry *LPM(uint32_t ip_dest)
{
	struct route_table_entry *next_hop = NULL;

	for (int i = 0; i < rtable_len; i++)
	{
		if (router_tbl[i].prefix == (router_tbl[i].mask & ip_dest))
		{
			// implementare cautare liniara
			// trebuie modificat la 2
			if (next_hop == NULL || (ntohl(router_tbl[i].mask) > ntohl(next_hop->mask)))
			{
				next_hop = &router_tbl[i];
			}
		}
	}
	return next_hop;
}

struct arp_entry mac_tbl[100000];
int mac_table_len;

// imi intoarce o intrare din tabela mac ce corespune cu urmatoarea statie destinatie
struct arp_entry *get_mac_entry(uint32_t ip_dest)
{
	for (int i = 0; i < mac_table_len; i++)
	{
		if (ip_dest == mac_tbl[i].ip)
		{
			return &mac_tbl[i];
		}
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	/* Read the static routing table and the MAC table */
	rtable_len = read_rtable(argv[1], router_tbl);
	mac_table_len = parse_arp_table("arp_table.txt", mac_tbl);

	// Do not modify this line
	init(argc - 2, argv + 2);

	while (1)
	{
		int interface;
		size_t len;
		interface = recv_from_any_link(buf, &len);
		glen = len;
		struct ether_header *eth_hdr = (struct ether_header *)buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		// daca ethernet incapsuleaza protocol de tip IPv4

		// adresa mac a interfetei pe care intra pachetul in ruter
		uint8_t mac_adress[6];
		get_interface_mac(interface, mac_adress);
		printf("ADRESA MAC A INTERFETEI PE CARE INTRA PACHETUL: ");
		// header ip
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
		// daca am ip
		if (eth_hdr->ether_type == htons(0x0800))
		{
			//  verific daca pachetul intra in ruter
			int ok = 0;
			for (int i = 0; i < 6; i++)
			{
				if (mac_adress[i] == eth_hdr->ether_dhost[i])
				{
					ok = 1;
				}
				else
				{
					ok = 0;
					break;
				}
			}
			if (ok == 1)
			{
				ICMP(0, 0, eth_hdr, mac_adress, ip_hdr, buf, interface);
				if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != 0)
				{
					printf("pachet incorect\n");
					continue;
				}
				if (ip_hdr->ttl == 0  || ip_hdr->ttl == 1)
				{
					ICMP(11, 0, eth_hdr, mac_adress, ip_hdr, buf, interface);
					continue;
					
				}
				ip_hdr->ttl--;
				// recalculare checksum
				ip_hdr->check = 0;
				ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

				// gasire next-hop

				struct route_table_entry *next_hop;
				next_hop = LPM(ip_hdr->daddr);

				if (next_hop == NULL)
				{
					ICMP(3, 0, eth_hdr, mac_adress, ip_hdr, buf, interface);
					continue;
				}

				// modificare adresa sursa si adresa destinatie din headerul ethernet

				struct arp_entry *mac_entry;
				mac_entry = get_mac_entry(next_hop->next_hop); // intrarea din tabela de mac-uri pt next-hop
				// adresa sursa este inlocuita cu adresa interfetei pe care pachetul iese din ruter
				get_interface_mac(next_hop->interface, eth_hdr->ether_shost);
				// adresa destinatie este inlocuita cu adresa mac a next-hop
				memcpy(eth_hdr->ether_dhost, mac_entry->mac, 6);
				// trimitere pachet mai departe
				send_to_link(next_hop->interface, buf, len);
			}
		}
		if (eth_hdr->ether_type == htons(0x0806))
		{
			printf("\nPROTOCOL ARP\n");
		}
	}
}
