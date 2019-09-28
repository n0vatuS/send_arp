// #pragma once
#include <pcap.h>

u_char * getTargetMACAddress(pcap_t* handle, char * src_ip, char * des_ip);