/* Autor: Damian Pukaluk */
/* Nr indeksu: 280427 */

#include "send_packets.h"

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
