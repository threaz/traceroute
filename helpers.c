/* Autor: Damian Pukaluk */
/* Nr indeksu: 280427 */

#include "helpers.h"

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

void print_usage()
{
  fprintf(stdout, "Usage: tr host\n");
}
