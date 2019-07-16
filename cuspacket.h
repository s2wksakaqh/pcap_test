#include <stdint.h>
#include <stdio.h>
#include <pcap.h>
#pragma once

void printEthernet(const u_char* packet);
void printIp(const u_char* packet);
void printTcp(const u_char* packet);
void printData(const u_char* packet);
uint16_t ntohs(uint16_t word);

