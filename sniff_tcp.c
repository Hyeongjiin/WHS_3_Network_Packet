#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6]; // destination host address 
    u_char  ether_shost[6]; // source host address 
    u_short ether_type;     // protocol type (IP, ARP, RARP, etc) 
} __attribute__((packed));

/* IP header */
struct ipheader {
    unsigned char      iph_ihl:4;  //IP header length (32bits word)
    unsigned char      iph_ver:4;  //IP version
    unsigned char      iph_tos;    //Type of service
    unsigned short int iph_len;   //IP Packet length (data + header)
    unsigned short int iph_ident;   //Identification
    unsigned short int iph_flag:3; //Fragmentation flags
    unsigned short int iph_offset:13; //Flags offset
    unsigned char      iph_ttl;    //Time to Live
    unsigned char      iph_protocol;  //Protocol type
    unsigned short int iph_chksum;  //IP datagram checksum
    struct in_addr     iph_sourceip; //Source IP address
    struct in_addr     iph_destip;   //Destination IP address
} __attribute__((packed));

/* TCP header */
struct tcpheader {
    u_short tcph_srcport;  // Source Port
    u_short tcph_destport; // Desitination Port
    u_int   tcph_seqnum;   // Sequence Number 
    u_int   tcph_acknum;   // Acknowledgement Number
    u_char  tcph_offset_byte; // Date Offset(Upper 4 bits) and Reserved(Lower 4bits) 
    u_char  tcph_flags;     // Flags (CWR, ECE, URG, ACK, PSH, PST, SYN, FIN)
    u_short tcph_window;    // Window
    u_short tcph_chksum;    // Checksum
    u_short tcph_urgptr;    // Urgent Pointer
} __attribute__((packed));

/* 패킷 처리 함수 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    /* Ethernet 헤더 파싱 */
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { /* IP 패킷 확인 */
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        
        if (ip->iph_protocol == IPPROTO_TCP) { /* TCP 프로토콜 확인 */
            /* IP 헤더 길이 계산 (iph_ihl은 32비트 워드 단위이므로 4를 곱함) */
            int ip_header_len = ip->iph_ihl * 4;

            /* TCP 헤더 파싱 */
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);

            /* TCP 헤더 길이 계산 (데이터 오프셋은 상위 4비트에 있음) */
            int tcph_offset = (tcp->tcph_offset_byte >> 4) & 0x0F;
            int tcp_header_len = tcph_offset * 4;

            /* 페이로드 시작 위치 및 길이 계산 */
            const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;
            int payload_len = header->len - (sizeof(struct ethheader) + ip_header_len + tcp_header_len);

            /* 소스 MAC 주소 출력 */
            printf("Ethernet Header Src MAC: ");
            for (int i = 0; i < 6; i++) {
                printf("%02x", eth->ether_shost[i]);
                if (i < 5) printf(":");
            }
            printf("\n");

            /* 목적지 MAC 주소 출력 */
            printf("Ethernet Header Dst MAC: ");
            for (int i = 0; i < 6; i++) {
                printf("%02x", eth->ether_dhost[i]);
                if (i < 5) printf(":");
            }
            printf("\n");

            /* 소스 IP 주소 출력 */
            printf("IP Header Src IP: %s\n", inet_ntoa(ip->iph_sourceip));

            /* 목적지 IP 주소 출력 */
            printf("IP Header Dst IP: %s\n", inet_ntoa(ip->iph_destip));

            /* 소스 포트 출력 */
            printf("TCP Header Src Port: %d\n", ntohs(tcp->tcph_srcport));

            /* 목적지 포트 출력 */
            printf("TCP Header Dst Port: %d\n", ntohs(tcp->tcph_destport));

            /* 메시지 (페이로드) 출력: 최대 20바이트 */
            printf("Message: ");
            int to_print = (payload_len < 50) ? payload_len : 50;
            for (int i = 0; i < to_print; i++) {
                printf("%02x ", payload[i]);
            }
            printf("\n\n");
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; /* TCP 패킷만 캡처 */
    bpf_u_int32 net;

    /* 네트워크 인터페이스에서 라이브 캡처 시작 */
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "디바이스 열기 실패: %s\n", errbuf);
        return 2;
    }

    /* 필터 컴파일 */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "필터 파싱 실패 %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    /* 필터 설정 */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "필터 설치 실패 %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    /* 패킷 캡처 시작 */
    pcap_loop(handle, -1, got_packet, NULL);

    /* 핸들 닫기 */
    pcap_close(handle);
    return 0;
}