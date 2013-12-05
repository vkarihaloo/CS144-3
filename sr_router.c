/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
	/* REQUIRES */
	assert(sr);

	/* Initialize cache and cache cleanup thread */
	sr_arpcache_init(&(sr->cache));

	pthread_attr_init(&(sr->attr));
	pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_t thread;

	pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

	/* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/
struct sr_rt* sr_rt_find(struct sr_instance* sr, uint32_t dst){
    struct sr_rt* now_rt;
    int best=0,current;
    struct sr_rt* best_rt=NULL;
    for (now_rt = sr->routing_table;now_rt!=NULL;now_rt = now_rt->next){
    	current = (int)(inet_addr(inet_ntoa(now_rt->dest))&inet_addr(inet_ntoa(now_rt->mask))&dst);
        if (current>best)
            best_rt = now_rt;
    }
    return best_rt;
}
void sr_handlepacket(struct sr_instance* sr,
		uint8_t * packet/* lent */,
		unsigned int len,
		char* interface/* lent */)
{
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);
	struct sr_if* if_now;
	struct sr_ethernet_hdr* e_hdr = NULL;
	struct sr_ip_hdr* ip_hdr = NULL;
	struct sr_icmp_hdr* icmp_hdr;
	struct sr_arp_hdr* a_hdr;
	uint8_t* newpacket;
	struct sr_ethernet_hdr* new_ethernet_hdr = NULL;
	struct sr_ip_hdr* new_ip_hdr = NULL;
	struct sr_icmp_hdr* new_icmp_hdr;
	struct sr_icmp_t3_hdr* new_icmp_t3_hdr;
	int new_len;

	struct sr_arpentry* entry;
	struct sr_rt* rt;
	printf("*** -> Received packet of length %d \n",len);
	if (len < sizeof(struct  sr_ethernet_hdr))
		return;
	e_hdr = (struct sr_ethernet_hdr*)packet;
	if (e_hdr->ether_type == htons(ethertype_ip)){
		printf("Receive IP packet\n");
		if (len<sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_ip_hdr))
			return;
		ip_hdr = (struct sr_ip_hdr*)(packet+sizeof(struct sr_ethernet_hdr));
		if (cksum((void*)ip_hdr,sizeof(struct sr_ip_hdr))!=0)
			return;
		if_now = sr_get_interface(sr, interface);
		if (if_now!=0){
			printf("The packet is for me\n");
			if (ip_hdr->ip_p==ip_protocol_icmp){
				printf("It's an ICMP packet\n");
				icmp_hdr = (struct sr_icmp_hdr*)(packet+sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_ip_hdr));
				if (cksum((void*)icmp_hdr,sizeof(struct sr_icmp_hdr))!=0){
					printf("Incorrect checksum\n");
					return;
				}
				if (icmp_hdr->icmp_type==icmp_type_echorequest){
					printf("PING request\n");
					newpacket = (uint8_t*)malloc(len);
					memcpy(newpacket,packet,len);
					new_ip_hdr = (struct sr_ip_hdr*)(newpacket+sizeof(struct sr_ethernet_hdr));
					new_icmp_hdr = (struct sr_icmp_hdr*)(newpacket+sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_ip_hdr));
					new_ip_hdr->ip_src = ip_hdr->ip_dst;
					new_ip_hdr->ip_dst = ip_hdr->ip_src;
					new_ip_hdr->ip_ttl = 64;
					new_ip_hdr->ip_sum = 0;
					new_ip_hdr->ip_sum = htons(cksum((void*)new_ip_hdr,sizeof(struct sr_ip_hdr)));
					gen_icmp_hdr(new_icmp_hdr,htons(icmp_type_echoreply),0);
					sr_handlepacket(sr, newpacket,len, interface);
					free(newpacket);
				}
			}
			else{
				printf("For me but not PING, send ICMP unreachable\n");
				new_len = sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_ip_hdr)+sizeof(struct sr_icmp_t3_hdr);
				newpacket = malloc(new_len);
				new_ethernet_hdr = (struct sr_ethernet_hdr*)packet;
				new_ip_hdr = (struct sr_ip_hdr*)(newpacket+sizeof(struct sr_ethernet_hdr));
				new_icmp_t3_hdr = (struct sr_icmp_t3_hdr*)(newpacket+sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_ip_hdr));
				gen_icmp_t3_hdr(new_icmp_t3_hdr,3);
				gen_ip_hdr(new_ip_hdr, ip_hdr->ip_dst, ip_hdr->ip_src, ip_protocol_icmp, sizeof(struct sr_ip_hdr)+sizeof(struct sr_icmp_t3_hdr));
				new_ethernet_hdr->ether_type = htons(ethertype_ip);
				sr_handlepacket(sr, newpacket,new_len, interface);
				free(newpacket);
			}
		}
		else{//forward
			rt = sr_rt_find(sr, ip_hdr->ip_dst);
			if (rt!=NULL){
				entry = sr_arpcache_lookup(&(sr->cache), inet_addr(inet_ntoa(rt->gw)));
				if (entry!=NULL){
					memcpy(e_hdr->ether_shost, sr_get_interface(sr, interface)->addr, 6);
					memcpy(e_hdr->ether_dhost, entry->mac, 6);
					ip_hdr->ip_ttl= ip_hdr->ip_ttl-1;
					ip_hdr->ip_sum = 0;
					sr_send_packet(sr, packet, len, interface);
				}
				else{
					sr_arpcache_queuereq(&(sr->cache),inet_addr(inet_ntoa(rt->gw)),packet,len,if_now);
				}
			}//send ICMP unreachable
			else{
				new_len = sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_ip_hdr)+sizeof(struct sr_icmp_hdr);
				newpacket = malloc(new_len);
				new_ethernet_hdr = (struct sr_ethernet_hdr*)packet;
				new_ip_hdr = (struct sr_ip_hdr*)(newpacket+sizeof(struct sr_ethernet_hdr));
				new_icmp_t3_hdr = (struct sr_icmp_t3_hdr*)(newpacket+sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_ip_hdr));
				gen_icmp_t3_hdr(new_icmp_t3_hdr,0);
				gen_ip_hdr(new_ip_hdr, ip_hdr->ip_dst, ip_hdr->ip_src, ip_protocol_icmp, sizeof(struct sr_ip_hdr)+sizeof(struct sr_icmp_t3_hdr));
				sr_handlepacket(sr, newpacket, new_len, interface);
				free(newpacket);
			}
		}
	}
	else if (e_hdr->ether_type == htons(ethertype_arp)){
		a_hdr = (struct sr_arp_hdr*)packet+sizeof(struct sr_ethernet_hdr);
		if_now = sr_get_interface(sr, interface);
		if ((a_hdr->ar_tip)==if_now->ip){
			if(a_hdr->ar_op == arp_op_request){//send a reply
				new_len = sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_arp_hdr)+4;
				newpacket = malloc(new_len);
				assert(packet);
				e_hdr = (struct sr_ethernet_hdr*)packet;
				a_hdr = (struct sr_arp_hdr*)packet+sizeof(struct sr_ethernet_hdr);
				gen_arp_hdr(a_hdr, icmp_type_echoreply, if_now->addr, if_now->ip, a_hdr->ar_sha, a_hdr->ar_tip);
				memcpy(e_hdr->ether_dhost,a_hdr->ar_sha,6);
				memcpy(e_hdr->ether_shost,if_now->addr,6);
				e_hdr->ether_type = htons(ethertype_ip);
				sr_send_packet(sr, newpacket, new_len, interface);
				free(newpacket);
			}
			else{//catch it
				sr_arpcache_insert(&(sr->cache), a_hdr->ar_sha, a_hdr->ar_sip);
			}
		}
	}
}/* end sr_ForwardPacket */

void gen_ip_hdr(struct sr_ip_hdr* ip_hdr, uint32_t src, uint32_t dst, uint8_t ip_p, int len){
	ip_hdr->ip_hl = sizeof(struct sr_ip_hdr)/4;
	ip_hdr->ip_v = 4;
	ip_hdr->ip_len = len;
	ip_hdr->ip_id = 0;
	ip_hdr->ip_off = 0;
	ip_hdr->ip_ttl = 64;
	ip_hdr->ip_p = ip_p;
	ip_hdr->ip_src = src;
	ip_hdr->ip_dst = dst;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = cksum((void*)ip_hdr,sizeof(struct sr_ip_hdr));
}

void gen_icmp_hdr(struct sr_icmp_hdr* icmp_hdr, uint8_t icmp_type, uint8_t icmp_code){
	icmp_hdr->icmp_type = icmp_type;
	icmp_hdr->icmp_code = icmp_code;
	icmp_hdr->icmp_sum = 0;
	icmp_hdr->icmp_sum = htons(cksum((void*)icmp_hdr,sizeof(struct sr_icmp_hdr)));
}

void gen_icmp_t3_hdr(struct sr_icmp_t3_hdr* icmp_hdr, uint8_t icmp_code){
	icmp_hdr->icmp_type = 3;
	icmp_hdr->icmp_code = icmp_code;
	icmp_hdr->icmp_sum = 0;
	icmp_hdr->icmp_sum = htons(cksum((void*)icmp_hdr,sizeof(struct sr_icmp_hdr)));
}
void gen_arp_hdr(struct sr_arp_hdr* a_hdr,
		uint16_t ar_op,
		unsigned char*   ar_sha,   /* sender hardware address      */
		uint32_t        ar_sip,             /* sender IP address            */
		unsigned char*   ar_tha,
		uint32_t        ar_tip){
	int i=0;
	a_hdr->ar_hrd=arp_hrd_ethernet;
	a_hdr->ar_pro=ethertype_ip;
	a_hdr->ar_hln=ETHER_ADDR_LEN;
	a_hdr->ar_pln=4;
	a_hdr->ar_op = ar_op;
	if (ar_sha!=NULL){
		for (i = 0;i < ETHER_ADDR_LEN; i++){
			a_hdr->ar_sha[i]=ar_sha[i];
		}
	}
	if (ar_tha!=NULL){
		for (i = 0;i < ETHER_ADDR_LEN; i++){
			a_hdr->ar_tha[i]=ar_tha[i];
		}
	}
	a_hdr->ar_sip = ar_sip;
	a_hdr->ar_tip = ar_tip;
}
