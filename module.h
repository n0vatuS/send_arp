// #pragma once
#include <pcap.h>
#include <stdlib.h>

void printMacAddress(u_char * mac, char * text);
uint8_t * parseIP(char * ori_ip);
uint8_t * getRouterIPAddress(void);
u_char * makeArpPacket(u_char * src_mac, u_char * des_mac, uint8_t * src_ip, uint8_t * des_ip);
u_char * getSenderMacAddress(char * dev);
u_char * getTargetMacAddress(pcap_t* handle, u_char * sender_mac_address, uint8_t * src_ip, uint8_t * des_ip);