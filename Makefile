Flags = -std=gnu99 -Wall -Wextra
CP = gcc


traceroute : Makefile display_packets.o get_packets.o helpers.o send_packets.o traceroute.c
				$(CP) $(Flags) -o traceroute traceroute.c display_packets.o get_packets.o helpers.o send_packets.o

display_packets.o : Makefile   display_packets.c display_packets.h
				$(CP) -c $(Flags) display_packets.c -o display_packets.o

get_packets.o : Makefile   get_packets.c get_packets.h
				$(CP) -c $(Flags) get_packets.c -o  get_packets.o

helpers.o : Makefile helpers.c helpers.h
				$(CP) -c $(Flags) helpers.c -o  helpers.o

send_packets.o : Makefile send_packets.c send_packets.h
				$(CP) -c $(Flags) send_packets.c -o  send_packets.o

clean:
				rm -f *.o

distclean: clean
				rm -f traceroute
