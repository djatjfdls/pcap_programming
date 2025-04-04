#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"
#define MAX_HTTP_MSG_LEN 1024

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 
    if (ip->iph_protocol == IPPROTO_TCP) { // TCP 패킷만 처리
        struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4));

        printf("\n================================\n");
        printf("[Ethernet Header]\n");
        printf("Src MAC : ");
        for(int i = 0; i < 6; i++) {
            printf("%02x", eth->ether_shost[i]);
    	    if(i != 5) printf(":");
        }
	printf("\n");
	printf("Dst MAC : ");
        for(int i = 0; i < 6; i++) {
            printf("%02x", eth->ether_dhost[i]);
          if(i != 5) printf(":");
        }
        printf("\n\n");

        printf("[IP Header]\n");
        printf("Src IP : %s\n", inet_ntoa(ip->iph_sourceip));   
        printf("Dst IP : %s\n", inet_ntoa(ip->iph_destip));    
        printf("\n");

	printf("[TCP Header]\n");
	printf("Src Port: %d\n", ntohs(tcp->tcp_sport));
        printf("Dst Port: %d\n", ntohs(tcp->tcp_dport));
        printf("\n");


        const char *message = (char *)(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4) + (tcp->tcp_offx2 >> 4) * 4);
        int message_len = ntohs(ip->iph_len) - ((ip->iph_ihl * 4) + (tcp->tcp_offx2 >> 4) * 4);

        // HTTP 메시지 출력 (최대 1024바이트)
        if (message_len > 0 && (tcp->tcp_flags & (TH_PUSH | TH_ACK))) {
            printf("HTTP Message : \n");

            for (int i = 0; i < message_len && i < MAX_HTTP_MSG_LEN; i++) {
                if (message[i] == '\r' || message[i] == '\n') {
                    printf("\n");
                } else {
                    printf("%c", message[i]);
                }
            }
            printf("\n");
        }

        /* determine protocol */
	switch(ip->iph_protocol) {                                 
            case IPPROTO_TCP:
                printf("Protocol: TCP\n");
                return;
            case IPPROTO_UDP:
                printf("Protocol: UDP\n");
                return;
            case IPPROTO_ICMP:
                printf("Protocol: ICMP\n");
                return;
            default:
                printf("Protocol: others\n");
                return;
        }
    }
 }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp port 80";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}
