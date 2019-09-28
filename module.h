// #pragma once
#include <pcap.h>
#include <stdlib.h>

uint8_t * parseIP(char * ori_ip);
uint8_t * getSenderMacAddress(char * dev);
uint8_t * makeArpPacket(uint8_t * src_mac, uint8_t * src_ip, uint8_t * des_ip);
u_char * getTargetMacAddress(pcap_t* handle, char * dev, char * src_ip, char * des_ip);