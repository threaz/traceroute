#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <limits.h>
#include <time.h>

/* GLOBALS */
pid_t pid = -1;
int seq_num = 0;
/* END GLOBALS */

/* STRUCTS */

struct record_out {
  int ttl;
  int seq;
  struct timeval time;
};

struct record_in {
  u_int8_t packet[IP_MAXPACKET + 1];
  struct timeval time;
  struct sockaddr_in sender;
};
/* END STRUCTS */

u_int16_t compute_icmp_checksum (const void *buff, int length)
{
	u_int32_t sum;
	const u_int16_t* ptr = buff;
	assert(length % 2 == 0);
	for (sum = 0; length > 0; length -= 2)
		sum += *ptr++;
	sum = (sum >> 16) + (sum & 0xffff);
	return (u_int16_t)(~(sum + (sum >> 16)));
}

void print_usage()
{
  fprintf(stdout, "Usage: tr host\n");
}

struct icmphdr make_icmp_header()
{
  struct icmphdr icmp_header;
  icmp_header.type = ICMP_ECHO;
  icmp_header.code = 0;
  icmp_header.un.echo.id = htons(pid);
  icmp_header.un.echo.sequence = htons(seq_num);
  icmp_header.checksum = 0;
  icmp_header.checksum = compute_icmp_checksum((u_int16_t*)&icmp_header, sizeof(icmp_header));

  return icmp_header;
}

ssize_t send_packet(int sockfd, struct sockaddr_in* addr_to, struct record_out* rec_out, int* ttl)
{
  struct icmphdr icmp_header = make_icmp_header();
  (*rec_out).ttl = *ttl;
  (*rec_out).seq = seq_num++;
  gettimeofday(&((*rec_out).time), NULL);

  if(setsockopt(sockfd, IPPROTO_IP, IP_TTL, ttl, sizeof(int))) {
    fprintf(stderr, "send_packet_with_ttl error: %s\n", strerror(errno));
    return -1;
  }

  ssize_t bytes_sent = sendto (sockfd,
                               &icmp_header,
                               sizeof(icmp_header),
                               0,
                               (struct sockaddr*)addr_to,
                               sizeof(*addr_to)
                               );

  return bytes_sent;
}

ssize_t get_packet(int sockfd, struct timeval* tv, struct record_in* rec_in)
{
  struct sockaddr_in sender;
  socklen_t          sender_len = sizeof(sender);
  u_int8_t           buffer[IP_MAXPACKET+1];
  fd_set             descriptors;

  FD_ZERO(&descriptors);
  FD_SET(sockfd, &descriptors);

  // TODO: handle timeout by hand
  int ready = select(sockfd+1, &descriptors, NULL, NULL, tv);

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

void get_packet_info(u_int8_t* packet, int* seq, int* pid, int* type)
{
  u_int8_t icmp_header_len = 8; // in bytes
  struct iphdr* ip_header = (struct iphdr*) packet;

  u_int8_t ip_header_len = 4 * ip_header->ihl;
  u_int8_t* icmp_packet = packet + ip_header_len;

  struct icmphdr* icmp_header = (struct icmphdr*) icmp_packet;

  if(type)
    *type = icmp_header->type;


  if(icmp_header->type == ICMP_TIME_EXCEEDED) {
    u_int8_t* icmp_data_ip_header = (void *)(icmp_header) + icmp_header_len;
    struct icmphdr* icmp_data_icmp_header = (struct icmphdr*)(icmp_data_ip_header + ip_header_len);
    if(pid)
      *pid = ntohs(icmp_data_icmp_header->un.echo.id);
    if(seq)
      *seq = ntohs(icmp_data_icmp_header->un.echo.sequence);
  } else if(icmp_header->type == ICMP_ECHOREPLY) {
    if(pid)
      *pid = ntohs(icmp_header->un.echo.id);
    if(seq)
      *seq = ntohs(icmp_header->un.echo.sequence);
  }
}

ssize_t is_record_from_current_round(struct record_in* rec, int seq_min, int seq_max)
{
  int seq;
  get_packet_info(rec->packet, &seq, NULL, NULL);
  return seq >= seq_min && seq <= seq_max;
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

void display_packets_info(struct record_out* recs_out, struct record_in* recs_in, ssize_t n_pcks, ssize_t max_packets, int ttl)
{
  char sender_ip_str[20];
  u_int32_t last_packet_src = 0;
  int32_t elapsed_usecs = 0.0;

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
        int32_t sec_diff  = (recs_in + i)->time.tv_sec - (recs_out + j)->time.tv_sec;
        int32_t usec_diff = sec_diff > 0 ? (1000000 - (recs_out + j)->time.tv_usec + (recs_in + i)->time.tv_usec)
          : ((recs_in + i)->time.tv_usec - (recs_out + j)->time.tv_usec);

        elapsed_usecs += sec_diff > 0 ? (sec_diff - 1) * 1000000 + usec_diff : usec_diff;

        break;
      }
    }

    last_packet_src = cur_sender.sin_addr.s_addr;
  }
  if(n_pcks != max_packets)
    printf(" ???");
  else {
    printf(" %ldms", (elapsed_usecs / n_pcks) / 1000);
  }

  printf("\n");
}

ssize_t traceloop(struct sockaddr_in* addr_to)
{
  int ttl = 1;
  const int n_packets = 3;
  const int ttl_max   = 30;
  const int tm_lim    = 1; // 1 sec

  struct record_out records_out[n_packets];
  struct record_in  records_in[n_packets];

  int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sockfd < 0) {
		fprintf(stderr, "socket error: %s\n", strerror(errno));
		return -1;
	}

  for(int i = 0; i < ttl_max; ++i) {
    for(int j = 0; j < n_packets; ++j)
      send_packet(sockfd, addr_to, records_out + j, &ttl);

    ssize_t n = get_packets(sockfd, records_in, n_packets, tm_lim, ttl);

    display_packets_info(records_out, records_in, n, n_packets, ttl);
    if(n > 0) {
      int type;
      get_packet_info(records_in[0].packet, NULL, NULL, &type);
      if(type == ICMP_ECHOREPLY)
        break;
    }

    ++ttl;
  }

  return EXIT_SUCCESS;
}

int main(int argc, char** argv)
{
  if(argc != 2) {
    print_usage(); // czy na pewno na stdout?
    return EXIT_FAILURE;
  }

  struct sockaddr_in addr;
  bzero(&addr, sizeof(addr));
  if(! inet_pton(AF_INET, argv[1], &(addr.sin_addr))) {
    fprintf(stderr, "Address ip is not correct.\n");
    return EXIT_FAILURE;
  }
  addr.sin_family = AF_INET;
  pid = getpid();

  traceloop(&addr);
  return EXIT_SUCCESS;
}
