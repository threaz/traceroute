/* Autor: Damian Pukaluk */
/* Nr indeksu: 280427 */

#include <unistd.h>

#include "send_packets.h"
#include "get_packets.h"
#include "display_packets.h"

/* GLOBALS */
pid_t pid = -1;
int seq_num = 0;
/* END GLOBALS */

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
    print_usage();
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

  int status = traceloop(&addr);
  return status;
}
