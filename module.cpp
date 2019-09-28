#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <ifaddrs.h>
#include <errno.h>

#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include "module.h"

#define IP_ADDR_LEN 4

uint8_t * parseIP(char * ori_ip) { // parsing string(ip)
    uint8_t * ip = (uint8_t *)malloc(sizeof(uint8_t) * IP_ADDR_LEN);
    char * token = strtok(ori_ip, ".");

    for(int i = 0; token != NULL; i++) {
        ip[i] = atoi(token);
        token = strtok(NULL, ".");
    }

    return ip;
}

uint8_t * getSenderMacAddress(char * dev) {
    struct ifaddrs *if_addrs = NULL;
    struct ifaddrs *if_addr = NULL;

    if (0 == getifaddrs(&if_addrs)) {    
        for (if_addr = if_addrs; if_addr != NULL; if_addr = if_addr->ifa_next) {
            if(!strcmp(dev, if_addr -> ifa_name)) {
                printf("name : %s\n", if_addr->ifa_name);

                // MAC address
                if (if_addr->ifa_addr != NULL && if_addr->ifa_addr->sa_family == AF_LINK) {
                    struct sockaddr_dl* sdl = (struct sockaddr_dl *)if_addr->ifa_addr;
                    uint8_t * mac = (uint8_t *)malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
                    if (ETHER_ADDR_LEN == sdl->sdl_alen) {
                        memcpy(mac, LLADDR(sdl), sdl->sdl_alen);
                        printf("mac  : %02x:%02x:%02x:%02x:%02x:%02x\n\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                        freeifaddrs(if_addrs);
                        if_addrs = NULL;
                        return mac;
                    }
                }
            }
        }
    } 
    else {
        printf("getifaddrs() failed with errno =  %i %s\n", errno, strerror(errno));
        exit(1);
    }
    return NULL;
}

uint8_t * makeArpPacket(uint8_t * src_mac, uint8_t * src_ip, uint8_t * des_ip) {
    struct ether_header * ether_hdr = (struct ether_header *)malloc(sizeof(struct ether_header));

    uint8_t des_mac[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(ether_hdr -> ether_dhost, des_mac, ETHER_ADDR_LEN);
    memcpy(ether_hdr -> ether_shost, src_mac, ETHER_ADDR_LEN);
    ether_hdr -> ether_type = htons(ETHERTYPE_ARP);
    
    struct ether_arp * req = (struct ether_arp *)malloc(sizeof(struct ether_arp));
    
    req -> ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    req -> ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    req -> ea_hdr.ar_hln = ETHER_ADDR_LEN;
    req -> ea_hdr.ar_pln = 4;
    req -> ea_hdr.ar_op = htons(1);

    for(int i = 0; i < ETHER_ADDR_LEN; i++) {
        des_mac[i] = 0;
    }

    memcpy(req -> arp_sha, src_mac, ETHER_ADDR_LEN);
    memcpy(req -> arp_spa, src_ip, IP_ADDR_LEN);
    memcpy(req -> arp_tha, des_mac, ETHER_ADDR_LEN);
    memcpy(req -> arp_tpa, des_ip, IP_ADDR_LEN);

    uint8_t * packet = (uint8_t *)malloc(sizeof(struct ether_header) + sizeof(struct ether_arp));
    memcpy(packet, ether_hdr, sizeof(struct ether_header));
    memcpy(packet + sizeof(struct ether_header), req, sizeof(struct ether_arp));

    printf("Packet : ");
    for(int i = 0; i < sizeof(struct ether_header) + sizeof(struct ether_arp); i++) {
        printf("%02x ", packet[i]);
    }
    printf("\n");

    return packet;
}

uint8_t * getTargetMacAddress(pcap_t* handle, char * dev, char * src_ip, char * des_ip) {
    uint8_t * packet = makeArpPacket(getSenderMacAddress(dev), parseIP(src_ip), parseIP(des_ip));
    pcap_sendpacket(handle, packet, sizeof(struct ether_header) + sizeof(struct ether_arp));
}
