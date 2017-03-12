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

/* GLOBALS */
pid_t pid = -1;
int seq_num = 0;
/* END GLOBALS */

/* STRUCTS */

// struktura, która identyfikuje wysłany pakiet
// Używa do tego wartości, które oznaczają kolejno:
// - ttl, z którym pakiet opuszcza program
// - numer sekwencyjny, który został mu przydzielony
// - czas, w którym został nadany
struct record_out {
  int ttl;
  int seq;
  struct timeval time;
};

struct record_in {
  u_int8_t* packet;
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

ssize_t send_packet(struct sockaddr_in* addr_to, struct record_out* recs_out, int sockfd, int* ttl)
{
  struct icmphdr icmp_header = make_icmp_header();
  recs_out[seq_num].ttl = *ttl;
  recs_out[seq_num].seq = seq_num;
  gettimeofday(&(recs_out[seq_num].time), NULL);

  ++seq_num;

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

    rec_in->packet = (u_int8_t*)malloc(sizeof(u_int8_t) * packet_len);
    memcpy(rec_in->packet, buffer, packet_len);
    gettimeofday(&(rec_in->time), NULL);
    rec_in->sender = sender;

    return 0;
  }
}

ssize_t get_packets(struct record_in* recs_in, int sockfd, int n_pcks, int recs_max, int tm_lim)
{
  ssize_t cnt = 0;
  struct timeval tv; tv.tv_sec = tm_lim; tv.tv_usec = 0;
  while((tv.tv_sec > 0 || tv.tv_usec > 0) && cnt < recs_max && cnt < n_pcks) {
    struct record_in rec_in;
    int st = get_packet(sockfd, &tv, &rec_in);
    if(st == 0) {
      recs_in[cnt++] = rec_in;
    } else {
      return cnt > 0 ? cnt : st;
    }
  }

  return cnt;
}

void print_as_bytes (unsigned char* buff, ssize_t length)
{
	for (ssize_t i = 0; i < length; i++, buff++)
		printf ("%.2x ", *buff);
  printf("\n");
}


int display_packets_info(struct record_out* recs_out, struct record_in* recs_in, ssize_t n_pcks, int act_ttl, int max_pcks)
{
  int last_packets_cnt = 0;
  double av_time = 0.0;
  u_int32_t last_packet_src  = 0;
  char sender_ip_str[20];
  u_int8_t icmp_header_len = 8; // in bytes

  fprintf(stdout, "%d.", act_ttl);
  for(int i = 0; i < n_pcks && last_packets_cnt < max_pcks; ++i) {
    struct record_in* act = &recs_in[i];

    struct iphdr* ip_header = (struct iphdr*) act->packet;

    u_int8_t ip_header_len = 4 * ip_header->ihl;
    u_int8_t* icmp_packet = act->packet + ip_header_len;

    struct icmphdr* icmp_header = (struct icmphdr*) icmp_packet;

    if(icmp_header->type == 11) {
      u_int8_t* icmp_data_ip_header = (void *)(icmp_header) + icmp_header_len;
      struct icmphdr* icmp_data_icmp_header = (struct icmphdr*)(icmp_data_ip_header + ip_header_len);

      if(ntohs(icmp_data_icmp_header->un.echo.id) == pid) {
        u_int16_t seq = ntohs(icmp_data_icmp_header->un.echo.sequence);
        if(recs_out[seq].ttl == act_ttl) { // display only current packets
          bzero(sender_ip_str, sizeof sender_ip_str);
          inet_ntop(AF_INET, &(act->sender.sin_addr), sender_ip_str, sizeof(sender_ip_str));

          if(last_packet_src == 0 || (last_packet_src != act->sender.sin_addr.s_addr))
            fprintf(stdout, " %s", sender_ip_str);
          last_packet_src = act->sender.sin_addr.s_addr;

          last_packets_cnt++;
          av_time += (act->time.tv_sec + (double)(act->time.tv_usec) / 10e6 -
                      (recs_out[seq].time.tv_sec + (double)(recs_out[seq].time.tv_usec) / 10e6)) / n_pcks;
        }
      }
    } else if(icmp_header->type == 0) { // TODO: change numbers to appropriate constants
      bzero(sender_ip_str, sizeof sender_ip_str);
      inet_ntop(AF_INET, &(act->sender.sin_addr), sender_ip_str, sizeof(sender_ip_str));
      u_int16_t seq = ntohs(icmp_header->un.echo.sequence);
      av_time = (act->time.tv_sec + act->time.tv_usec / 10e6 -
                 (recs_out[seq].time.tv_sec + recs_out[seq].time.tv_usec / 10e6));
      fprintf(stdout, " %s %2.2fms\n", sender_ip_str, 10e3 * av_time);
      return 0;
    } // ignore otherwise
  }

  if(last_packets_cnt == 0)
    fprintf(stdout, "*");
  else if(last_packets_cnt == n_pcks)
    fprintf(stdout, " %2.2fms", 10e3 * av_time);
  else
    fprintf(stdout, " ???");

  puts("");
  return 1;
}

void cleanup(struct record_in* recs_in, int n)
{
  // TODO
}

ssize_t traceloop(struct sockaddr_in* addr_to)
{
  int ttl = 1;
  const int n_packets = 3;
  const int ttl_max   = 30;
  const int buf_max   = 1000;
  const int tm_lim    = 1; // 1 sec

  struct record_out records_out[buf_max];
  struct record_in records_in[buf_max];

  int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sockfd < 0) {
		fprintf(stderr, "socket error: %s\n", strerror(errno));
		return -3;
	}

  for(int i = 0; i < ttl_max; ++i) {
    for(int j = 0; j < n_packets; ++j) {
      send_packet(addr_to, records_out, sockfd, &ttl);
    }

    ssize_t n = get_packets(records_in, sockfd, n_packets, buf_max, tm_lim);

    int cd = display_packets_info(records_out, records_in, n, ttl, n_packets);
    cleanup(records_in, n);
    ++ttl;

    if(! cd)
      break;
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
    fprintf(stderr, "error: %s\n", strerror(errno));
    return EXIT_FAILURE;
  }
  addr.sin_family = AF_INET;
  pid = getpid();

  traceloop(&addr);
  return EXIT_SUCCESS;
}
