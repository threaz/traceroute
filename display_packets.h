#ifndef DISPLAY_PACKETS_H
#define DISPLAY_PACKETS_H

#include <stdlib.h>

#include "send_packets.h"
#include "get_packets.h"
#include "helpers.h"

void display_packets_info(struct record_out* recs_out, struct record_in* recs_in, ssize_t n_pcks, ssize_t max_packets, int ttl);

#endif
