#include <stdlib.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include "module.h"

#include <sys/ioctl.h>
#include <net/if.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>


uint8_t * parseIP(char * ori_ip) { // parsing string(ip)
    uint8_t * ip = (uint8_t *)malloc(sizeof(uint8_t) * 4);
    char * token = strtok(ori_ip, ".");

    for(int i = 0; token != NULL; i++) {
        ip[i] = atoi(token);
        token = strtok(NULL, ".");
    }

    return ip;
}

uint8_t * makeArpPacket(uint8_t * src_ip, uint8_t * des_ip) {
    struct ether_header * ether_hdr = (struct ether_header *)malloc(sizeof(struct ether_header));
    for(int i = 0; i < 6; i++)
        ether_hdr -> ether_dhost[i] = 0xff;
    ether_hdr -> ether_type = ETHERTYPE_ARP;
    
    struct ether_arp * req = (struct ether_arp *)malloc(sizeof(struct ether_arp));
    
    req -> ea_hdr.ar_hrd = 1;
    req -> ea_hdr.ar_pro = ETHERTYPE_IP;
    req -> ea_hdr.ar_hln = 6;
    req -> ea_hdr.ar_pln = 4;
    req -> ea_hdr.ar_op = 1;

    uint8_t src_mac[6], des_mac[6] = {0};

    memcpy(req -> arp_sha, src_mac, 6);
    memcpy(req -> arp_spa, src_ip, 4);
    memcpy(req -> arp_tha, des_mac, 6);
    memcpy(req -> arp_tpa, des_ip, 4);
}

uint8_t * getTargetMACAddress(pcap_t* handle, char * src_ip, char * des_ip) {
    makeArpPacket(parseIP(src_ip), parseIP(des_ip));
}
