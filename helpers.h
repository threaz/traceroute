#ifndef HELPERS_H
#define HELPERS_H

#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>

void get_packet_info(u_int8_t* packet, int* seq, int* pid, int* type);
void print_usage();

#endif
