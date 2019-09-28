// #pragma once
#include <pcap.h>
#include <stdlib.h>

uint8_t * parseIP(char * ori_ip);
u_char * getSenderMacAddress(char * dev);
u_char * makeArpPacket(u_char * src_mac, u_char * des_mac, uint8_t * src_ip, uint8_t * des_ip);
u_char * getTargetMacAddress(pcap_t* handle, u_char * sender_mac_address, char * src_ip, char * des_ip);