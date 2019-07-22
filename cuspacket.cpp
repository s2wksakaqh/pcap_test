#include "cuspacket.h"



struct eth_header
{
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint8_t etherType[2];
};

struct ip_header
{
    uint version : 4;
    uint header_length : 4;
    uint8_t TOS;
    uint16_t total_length;
    uint16_t identification;
    uint OF : 1;
    uint DF : 1;
    uint MF : 1;
    uint fragment_offset : 13;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t src_ip[6];
    uint8_t dest_ip[6];
};

struct tcp_header
{
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint header_len : 4;
    uint reserve_bit : 6;
    uint URG : 1;
    uint ACK : 1;
    uint PSH : 1;
    uint RST : 1;
    uint SYN : 1;
    uint FIN : 1;
    uint16_t window_size;
    uint16_t check_sum;
    uint16_t urgent_point;
};

uint16_t ntohs(uint16_t word)
{
    return (uint16_t)(word << 8| word >> 8);
}

void printEthernet(const u_char* packet)
{
    struct eth_header *ethernet_packet;
    ethernet_packet = (struct eth_header*)packet;
    printf("****************************************************\n");
    printf("ETHERNET HEADER\n");
    printf("dest mac : %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet_packet->dest_mac[0], ethernet_packet->dest_mac[1],ethernet_packet->dest_mac[2],ethernet_packet->dest_mac[3],ethernet_packet->dest_mac[4],ethernet_packet->dest_mac[5]);
    printf("src  mac : %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet_packet->src_mac[0], ethernet_packet->src_mac[1], ethernet_packet->src_mac[2], ethernet_packet->src_mac[3], ethernet_packet->src_mac[4], ethernet_packet->src_mac[5]);
    printf("type : %02x%02x\n", ethernet_packet->etherType[0], ethernet_packet->etherType[1]);

}


void printIp(const u_char* packet)
{
    struct ip_header* ip_packet;
    ip_packet = (struct ip_header*)&packet[14];
    printf("IP HEADER\n");
    printf("version : %d  header length : %d  type of service : %d  total length : %d\n", ip_packet->version, ip_packet->header_length, ip_packet->TOS, ntohs(ip_packet->total_length));
    printf("O flag : %d  D flag : %d  M flag : %d \n", ip_packet->DF, ip_packet->MF);
    printf("TTL : %d  Protocol : %d  Header Checksum : %d\n", ip_packet->ttl, ip_packet->protocol, ntohs(ip_packet->checksum));
    printf("src  ip : %d.%d.%d.%d\n", ip_packet->src_ip[0], ip_packet->src_ip[1], ip_packet->src_ip[2], ip_packet->src_ip[3]);
    printf("dest ip : %d.%d.%d.%d\n", ip_packet->dest_ip[0], ip_packet->dest_ip[1], ip_packet->dest_ip[2], ip_packet->dest_ip[3]);
}


void printTcp(const u_char* packet)
{
    struct tcp_header* tcp_packet;
    int ethernet_header_size=((uint8_t)packet[14] & 15)*4;
    tcp_packet = (struct tcp_header*)&packet[14+ethernet_header_size];
    printf("TCP HEADER\n");
    printf("src  port : %d\n", ntohs(tcp_packet->src_port));
    printf("dest port : %d\n", ntohs(tcp_packet->dest_port));
    printf("URG : %d  ACK : %d  PSH : %d  RST : %d  SYN : %d  FIN : %d\n", tcp_packet->URG, tcp_packet->ACK, tcp_packet->PSH, tcp_packet->RST, tcp_packet->SYN, tcp_packet->FIN);

}

void printData(const u_char* packet)
{
    int ethernet_header_size = ((uint8_t)packet[14] & 15)*4;
    int tcp_header_size = (((uint8_t)packet[14+ethernet_header_size+12] & 240)>>4)*4;
    int start_http_data = 14+ethernet_header_size+tcp_header_size;
    printf("bytes : ");
    for(int i = 0; i < 10; i++)
    {
       printf("%02x ", packet[start_http_data+i]);
    }
    printf("\n****************************************************\n");
}

