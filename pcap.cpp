#include <pcap.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include "pcap.h"

u_char * DataLinkLayer(const u_char * packet) {
    struct ether_header * ether_hdr = (struct ether_header *)packet;

    if(ntohs(ether_hdr -> ether_type) == ETHERTYPE_ARP) {
        u_char * tmp = NetworkLayer(packet);
        if(tmp) return tmp;
    }

    return NULL;
}

u_char * NetworkLayer(const u_char * packet) {
    struct ether_arp * res = (struct ether_arp *)(packet + DATALINK_HEADER_SIZE);

    if(ntohs(res -> ea_hdr.ar_op) == 2)
        return res -> arp_sha;
    else return NULL;
}