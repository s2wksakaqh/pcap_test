#include <pcap.h>
#include <stdint.h>
#include <cuspacket.h>

void usage() {
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
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

    while (true)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        if(packet[12]==0x08 && packet[13]==0x00)
        {
            if(packet[23]==0x06)
            {
                uint16_t src_port = (uint8_t)packet[34]<<8 | (uint8_t)packet[35];
                uint16_t dest_port = (uint8_t)packet[36]<<8 | (uint8_t)packet[37];
                if((src_port == 80) || (dest_port == 80))
                {
                    printf("%u bytes captured\n", header->caplen);
                    printEthernet(packet);
                    printIp(packet);
                    printTcp(packet);
                    printData(packet);
                }
            }
        }
    }
      pcap_close(handle);
      return 0;
}

