#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <errno.h>

#include "module.h"
#include "pcap.h"

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

u_char * getSenderMacAddress(char * dev) {
    struct ifaddrs *if_addrs = NULL;
    struct ifaddrs *if_addr = NULL;

    if (0 == getifaddrs(&if_addrs)) {    
        for (if_addr = if_addrs; if_addr != NULL; if_addr = if_addr->ifa_next) {
            if(!strcmp(dev, if_addr -> ifa_name)) {
                printf("name : %s\n", if_addr->ifa_name);

                // MAC address
                if (if_addr->ifa_addr != NULL && if_addr->ifa_addr->sa_family == AF_LINK) {
                    struct sockaddr_dl* sdl = (struct sockaddr_dl *)if_addr->ifa_addr;
                    u_char * mac = (uint8_t *)malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
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

u_char * makeArpPacket(u_char * src_mac, u_char * des_mac, uint8_t * src_ip, uint8_t * des_ip) {
    struct ether_header * ether_hdr = (struct ether_header *)malloc(sizeof(struct ether_header));

    memcpy(ether_hdr -> ether_shost, src_mac, ETHER_ADDR_LEN);
    memcpy(ether_hdr -> ether_dhost, des_mac, ETHER_ADDR_LEN);
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

    u_char * packet = (u_char *)malloc(sizeof(struct ether_header) + sizeof(struct ether_arp));
    memcpy(packet, ether_hdr, sizeof(struct ether_header));
    memcpy(packet + sizeof(struct ether_header), req, sizeof(struct ether_arp));

    printf("Packet : ");
    for(int i = 0; i < sizeof(struct ether_header) + sizeof(struct ether_arp); i++) {
        printf("%02x ", packet[i]);
    }
    printf("\n\n");

    return packet;
}

u_char * getTargetMacAddress(pcap_t* handle, u_char * sender_mac_address, char * src_ip, char * des_ip) {
    uint8_t broadcast[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    u_char * packet = makeArpPacket(sender_mac_address, broadcast, parseIP(src_ip), parseIP(des_ip));
    pcap_sendpacket(handle, packet, sizeof(struct ether_header) + sizeof(struct ether_arp));

    int cnt = 0;
    while (++cnt) {
        struct pcap_pkthdr * header;
        const u_char * packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        u_char * target_mac_address = DataLinkLayer(packet);
        if(target_mac_address) return target_mac_address;
    }
    return NULL;
}
