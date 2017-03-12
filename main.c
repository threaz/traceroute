#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>

#define N_PACKETS 3
#define N_SECONDS 1
#define TTL_MAX 2
#define BUFSIZE 1000

// struktura, która identyfikuje wysłany pakiet
// Używa do tego wartości, które oznaczają kolejno:
// - ttl, z którym pakiet opuszcza program
// - numer sekwencyjny, który został mu przydzielony
// - czas, w którym został nadany
/* struct record_out { */
/*   u_short ttl; */
/*   u_short seq; */
/*   struct timeval time; */
/* }; */

/* struct record_in { */
/*   u_int8_t packet[IP_MAXPACKET+1]; */
/*   struct timeval time; */
/*   struct sockaddr_in sender; */
/* }; */
/* size_t nseq = 0; */
/* int pid; */
/* struct record_out outgoing_records[BUFSIZE]; */

void print_as_bytes (unsigned char* buff, ssize_t length)
{
	for (ssize_t i = 0; i < length; i++, buff++)
		printf ("%.2x ", *buff);
}

/* void print_usage() */
/* { */
/*   fprintf(stdout, "Usage: tr host\n"); */
/* } */

u_int16_t compute_icmp_checksum (const void *buff, int length)
{
	u_int32_t sum;
	const u_int16_t* ptr = buff;
	/* assert(length % 2 == 0); */
	for (sum = 0; length > 0; length -= 2)
		sum += *ptr++;
	sum = (sum >> 16) + (sum & 0xffff);
	return (u_int16_t)(~(sum + (sum >> 16)));
}

struct icmphdr make_icmp_header()
{
  struct icmphdr icmp_header;
  icmp_header.type = ICMP_ECHO;
  icmp_header.code = 0;
  icmp_header.un.echo.id = htons(pid);
  icmp_header.un.echo.sequence = htons(nseq);
  icmp_header.checksum = 0;
  icmp_header.checksum = compute_icmp_checksum((u_int16_t*)&icmp_header, sizeof(icmp_header));

  return icmp_header;
}

ssize_t send_packet_with_ttl(struct sockaddr_in* to, int sockfd, int ttl)
{
  struct icmphdr icmp_header = make_icmp_header();
  struct record_out outgoing;
  outgoing.ttl = ttl;
  outgoing.seq = nseq;
  gettimeofday(&outgoing.time, NULL);

  outgoing_records[nseq++] = outgoing;

  if(setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int))) {
    fprintf(stderr, "send_packet_with_ttl error: %s\n", strerror(errno));
    return -1;
  }

  ssize_t bytes_sent = sendto (sockfd,
                               &icmp_header,
                               sizeof(icmp_header),
                               0,
                               (struct sockaddr*)to,
                               sizeof(*to)
                               );

  return bytes_sent;
}

void get_packet_sequential_number(u_int8_t* buffer, u_short* id, u_short* seq_num)
{
  struct iphdr* ip_header = (struct iphdr*) buffer;
  u_int8_t* icmp_packet = buffer + 4 * ip_header->ihl;
  u_int8_t* icmp_d = icmp_packet + 1 + 1 + 2 + 4 + 4 * ip_header->ihl + 1 + 1 + 2;

  print_as_bytes(icmp_d, 2);
  *id = ntohs((u_short*)icmp_d);
  *seq_num = ntohs((u_short*)(icmp_d + 2));
}

// Zwraca liczbę otrzymanych pakietów.
// Domyślnie czeka na n pakietów przez N_SECONDS sekund.
int get_n_packets(int sockfd, struct record_in* records, int n, int seq_num)
{
  struct sockaddr_in sender;
  socklen_t          sender_len;
  u_int8_t           buffer[IP_MAXPACKET+1];
  fd_set             descriptors;

  FD_ZERO(&descriptors);
  FD_SET(sockfd, &descriptors);

  struct timeval tv; tv.tv_sec = N_SECONDS; tv.tv_usec = 0;
  int ready = select (sockfd+1, &descriptors, NULL, NULL, &tv);
  int cnt = 0;

  if(ready < 0) {
    fprintf(stderr, "get_n_packets error: %s\n", strerror(errno));
    return -1;
  } else if(ready == 0) {
    return -2;
  } else {
    do {
      ssize_t packet_len = recvfrom (sockfd, buffer, IP_MAXPACKET, MSG_DONTWAIT,
                                     (struct sockaddr*)&sender, &sender_len);
      if (packet_len < 0) {
        fprintf(stderr, "recvfrom error: %s\n", strerror(errno));
        return -1;
      }

      u_short seq_num_from_packet, id_from_packet;
      get_packet_sequential_number(buffer, &seq_num_from_packet, &id_from_packet);
      printf("[+] %u %u\n", seq_num_from_packet, id_from_packet);
      if(seq_num_from_packet >= seq_num) {
        struct record_in s;
        memcpy(&(s.packet), buffer, IP_MAXPACKET); // TODO: zobacz, czy nie trzeba IP_MAXPACKET+1
        gettimeofday(&(s.time), NULL);
        s.sender = sender;
        memcpy(records + cnt, &s, sizeof(s));
        cnt++;
        n--;
      }

      ready = select(sockfd+1, &descriptors, NULL, NULL, &tv);
      if(ready < 0) {
        fprintf(stderr, "get_n_packets error: %s\n", strerror(errno));
        return -1;
      }
    } while(n > 0 && tv.tv_usec > 0 && ready > 0);
  }

  return cnt;
}

void print_records_info(const struct record_in* records, int n)
{
  /* char sender_ip_str[20]; */
  records = NULL;
  if(n > 0) {

  } else if(n == 0) {
    // TODO
  } else {
    // TODO
  }
}

int traceloop(struct in_addr* addr)
{
  int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sockfd < 0) {
		fprintf(stderr, "socket error: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

  int ttl_cnt = 1;
  struct record_in records_in[N_PACKETS];
  struct sockaddr_in recipient;
  bzero(&recipient, sizeof(recipient));
  recipient.sin_family = AF_INET;
  recipient.sin_addr   = *addr;

  for(int i = 0; i < TTL_MAX; ++i) {
    for(int j = 0; j < N_PACKETS; ++j) {
      printf("[+] %ld, %d\n", send_packet_with_ttl(&recipient, sockfd, ttl_cnt), ttl_cnt);
    }

    bzero(records_in, sizeof records_in / sizeof records_in[0]);
    int n = get_n_packets(sockfd, records_in, N_PACKETS, nseq-N_PACKETS);

    print_records_info(records_in, n);
    printf("[*] %d\n", n);
    ++ttl_cnt;
  }


  return EXIT_SUCCESS;
}

int main(int argc, char** argv)
{
  if(argc != 2) {
    print_usage(); // czy na pewno na stdout?
    return EXIT_FAILURE;
  }

  struct in_addr addr;
  pid = getpid();
  if(! inet_pton(AF_INET, argv[1], &addr)) {
    fprintf(stderr, "error: %s\n", strerror(errno));
    return EXIT_FAILURE;
  }

  traceloop(&addr);

	return EXIT_SUCCESS;
}

  /* for (;;) { */
	/* 	struct sockaddr_in 	sender; */
	/* 	socklen_t     			sender_len = sizeof(sender); */
	/* 	u_int8_t 		       	buffer[IP_MAXPACKET]; */
  /*   fd_set descriptors; */

  /*   FD_ZERO (&descriptors); */
  /*   FD_SET (sockfd, &descriptors); */
  /*   struct timeval tv; tv.tv_sec = N_SECONDS; tv.tv_usec = 0; */

  /*   int ready = select(sockfd+1, &descriptors, NULL, NULL, &tv); */
  /*   if(ready < 0) { */
  /*     fprintf(stderr, "receive_packets error: %s\n", strerror(errno)); */
  /*     return -1; */
  /*   } else if(ready > 0) { // timeout */
  /*     return -1; */
  /*   } else { // success */
  /*     /\* ssize_t packet_len = recvfrom(sockfd, buffer, IP_MAXPACKET, MSG_DONTWAIT, (struct sockaddr*)&sender, &sender_len);  *\/ */
  /*   } */

	/* 	ssize_t packet_len = recvfrom(sockfd, buffer, IP_MAXPACKET, MSG_DONTWAIT, (struct sockaddr*)&sender, &sender_len); */
	/* 	if (packet_len < 0) { */
	/* 		fprintf(stderr, "recvfrom error: %s\n", strerror(errno)); */
	/* 		return EXIT_FAILURE; */
	/* 	} */

	/* 	char sender_ip_str[20]; */
	/* 	inet_ntop(AF_INET, &(sender.sin_addr), sender_ip_str, sizeof(sender_ip_str)); */
	/* 	printf("Received IP packet with ICMP content from: %s\n", sender_ip_str); */

	/* 	struct iphdr* 		ip_header = (struct iphdr*) buffer; */
	/* 	ssize_t   				ip_header_len = 4 * ip_header->ihl; */

	/* 	printf("IP header: "); */
	/* 	print_as_bytes(buffer, ip_header_len); */
	/* 	printf("\n"); */

	/* 	printf("IP data:   "); */
	/* 	print_as_bytes(buffer + ip_header_len, packet_len - ip_header_len); */
	/* 	printf("\n\n"); */
	/* }  */
