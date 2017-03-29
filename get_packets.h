#ifndef GET_PACKETS_H
#define GET_PACKETS_H

#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>

#include "helpers.h"

struct record_in {
  u_int8_t packet[IP_MAXPACKET + 1];
  struct timeval time;
  struct sockaddr_in sender;
};

extern pid_t pid;

ssize_t get_packet(int sockfd, struct timeval* tv, struct record_in* rec_in);
ssize_t get_packets(int sockfd, struct record_in* recs_in, int n_pcks, int tm_lim, int ttl);
ssize_t is_record_from_current_round(struct record_in* rec, int seq_min, int seq_max);

#endif
