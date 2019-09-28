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

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  char* src_ip = argv[2];
  char* des_ip = argv[3];
  u_char * target_mac_address = getTargetMacAddress(handle, dev, src_ip, des_ip);
  printf("Target Mac Address : ");
  for(int i = 0; i < ETHER_ADDR_LEN ; i++) {
      printf("%02x", target_mac_address[i]);
      if(i != ETHER_ADDR_LEN - 1) printf(":");
  }
  printf("\n");

  pcap_close(handle);
  return 0;
}