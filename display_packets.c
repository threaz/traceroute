/* Autor: Damian Pukaluk */
/* Nr indeksu: 280427 */

#include "display_packets.h"

void display_packets_info(struct record_out* recs_out, struct record_in* recs_in,
                          ssize_t n_pcks, ssize_t max_packets, int ttl)
{
  char sender_ip_str[20];
  u_int32_t last_packet_src = 0;
  double elapsed = 0.0;

  printf("%d.", ttl);

  if(n_pcks <= 0) {
      printf(" *\n");
      return;
    }

  for(int i = 0; i < n_pcks; ++i) {
    struct sockaddr_in cur_sender = recs_in->sender;
    if(last_packet_src != cur_sender.sin_addr.s_addr) {
      bzero(sender_ip_str, sizeof sender_ip_str);
      inet_ntop(AF_INET, &(cur_sender.sin_addr), sender_ip_str, sizeof(sender_ip_str));
      printf(" %s", sender_ip_str);
    }

    // calc. time
    int seq;
    get_packet_info((recs_in + i)->packet, &seq, NULL, NULL);


    for(int j = 0; j < n_pcks; ++j) {
      if((recs_out + j)->seq == seq) {
        double hop_time =  (recs_in + i)->time.tv_sec - (recs_out + j)->time.tv_sec +
          ((double)((recs_in + i)->time.tv_usec - (recs_out + j)->time.tv_usec)) / 1000000;
        elapsed += hop_time;
        break;
      }
    }

    last_packet_src = cur_sender.sin_addr.s_addr;
  }
  if(n_pcks != max_packets)
    printf(" ???");
  else {
    printf(" %.0fms", (elapsed / n_pcks) * 1000);
  }

  printf("\n");
}
