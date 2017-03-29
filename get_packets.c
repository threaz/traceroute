/* Autor: Damian Pukaluk */
/* Nr indeksu: 280427 */

#include "get_packets.h"

ssize_t is_record_from_current_round(struct record_in* rec, int seq_min, int seq_max)
{
  int seq, rec_pid;
  get_packet_info(rec->packet, &seq, &rec_pid, NULL);
  return (seq >= seq_min && seq <= seq_max) && (rec_pid == pid);
}

void get_time_left(struct timeval to_pass, struct timeval before, struct timeval after, struct timeval* result)
{
  if(! result)
    return;

  double seconds_passed = (after.tv_sec - before.tv_sec) + ((double)(after.tv_usec - before.tv_usec))/ 1000000;
  double seconds_to_pass = to_pass.tv_sec + (double)(to_pass.tv_usec) / 1000000;

  double seconds_left = seconds_to_pass - seconds_passed;
  if(seconds_left <= 0)
    result->tv_sec = result->tv_usec = 0;
  else {
    result->tv_sec  = seconds_left / 1000000;
    result->tv_usec = (seconds_left - (seconds_left / 1000000)) * 1000000;
  }
}

ssize_t get_packet(int sockfd, struct timeval* tv, struct record_in* rec_in)
{
  struct sockaddr_in sender;
  socklen_t          sender_len = sizeof(sender);
  u_int8_t           buffer[IP_MAXPACKET+1];
  fd_set             descriptors;
  struct timeval     to_pass, time_before, time_after;

  FD_ZERO(&descriptors);
  FD_SET(sockfd, &descriptors);

  to_pass = *tv;
  gettimeofday(&time_before, NULL);
  int ready = select(sockfd+1, &descriptors, NULL, NULL, tv);
  gettimeofday(&time_after, NULL);

  get_time_left(to_pass, time_before, time_after, tv);

  if(ready == -1) {
    fprintf(stderr, "get_packet error: %s\n", strerror(errno));
    return -1;
  } else if(ready == 0) { // timeout
    return -2;
  } else {
    ssize_t packet_len = recvfrom(sockfd, buffer, IP_MAXPACKET, MSG_DONTWAIT,
                                   (struct sockaddr*)&sender, &sender_len);
    if (packet_len < 0) {
      fprintf(stderr, "recvfrom error: %s\n", strerror(errno));
      return -1;
    }

    memcpy(rec_in->packet, buffer, packet_len);
    gettimeofday(&(rec_in->time), NULL);
    rec_in->sender = sender;

    return 0;
  }
}

ssize_t get_packets(int sockfd, struct record_in* recs_in, int n_pcks, int tm_lim, int ttl)
{
  ssize_t cnt = 0;
  struct timeval tv; tv.tv_sec = tm_lim; tv.tv_usec = 0;

  while((tv.tv_sec > 0 || tv.tv_usec > 0) && cnt < n_pcks) {
    struct record_in rec_in;
    int status = get_packet(sockfd, &tv, &rec_in);
    if(status == 0) {
      int current_max_seq_num = ttl * n_pcks - 1,
        current_min_seq_num = current_max_seq_num - n_pcks + 1;

      if(! is_record_from_current_round(&rec_in, current_min_seq_num, current_max_seq_num))
        continue;

      struct record_in* act_record = recs_in + cnt;
      memcpy(act_record->packet, rec_in.packet, IP_MAXPACKET+1);
      act_record->time = rec_in.time;
      act_record->sender = rec_in.sender;

      ++cnt;
    } else {
      return cnt > 0 ? cnt : status;
    }
  }

  return cnt;
}
