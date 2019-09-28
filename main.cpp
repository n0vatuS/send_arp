#include <stdio.h>
#include <memory.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include "module.h"

void usage() {
  printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
  printf("sample: ex : send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
  if (argc != 4) {
    usage();
    return -1;
  }

  char * dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t * handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  uint8_t * src_ip = parseIP(argv[2]);
  uint8_t * des_ip = parseIP(argv[3]);
  printf("%u.%u.%u.%u", src_ip[0],src_ip[1],src_ip[2],src_ip[3]);
  
  uint8_t * router_ip = getRouterIPAddress();
  printf("%u.%u.%u.%u", router_ip[0],router_ip[1],router_ip[2],router_ip[3]);

  u_char * sender_mac_address = getSenderMacAddress(dev);
  char text1[30] = "Sender Mac Address : ";
  printMacAddress(sender_mac_address, text1);

  u_char * router_mac_address = getTargetMacAddress(handle, sender_mac_address, src_ip, router_ip);
  char text2[30] = "Router Mac Address : ";
  printMacAddress(router_mac_address, text2);

  u_char * target_mac_address = getTargetMacAddress(handle, sender_mac_address, src_ip, des_ip);
  char text3[30] = "Target Mac Address : ";
  printMacAddress(target_mac_address, text3);

  pcap_close(handle);
  return 0;
}