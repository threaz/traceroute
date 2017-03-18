#ifndef SEND_PACKETS_H
#define SEND_PACKETS_H

#include <netinet/ip_icmp.h>
#include <assert.h>
#include <sys/time.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

struct record_out {
  int ttl;
  int seq;
  struct timeval time;
};

extern pid_t pid;
extern int   seq_num;

struct icmphdr make_icmp_header();
u_int16_t compute_icmp_checksum (const void *buff, int length);
ssize_t send_packet(int sockfd, struct sockaddr_in* addr_to, struct record_out* rec_out, int* ttl);

#endif
