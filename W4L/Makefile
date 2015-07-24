CC = cc 
CFLAGS = -c -O2 -g 
WFLAGS = -Wall -Werror -Wno-error=deprecated-declarations 

alliwanttodo: client server
security.o: security.h security.c utility.h
	$(CC) $(CFLAGS) $(WFLAGS) security.c
utility.o: utility.h utility.c 
	$(CC) $(CFLAGS) $(WFLAGS) utility.c 
server.o: server.c security.h utility.h
	$(CC) $(CFLAGS) $(WFLAGS) server.c 
client.o: client.c security.h utility.h
	$(CC) $(CFLAGS) $(WFLAGS) client.c
server: server.o security.o utility.o
	$(CC) -o server security.o server.o utility.o -lcrypto 
client: client.o security.o utility.o
	$(CC) -o client security.o client.o utility.o -lcrypto

clean:
	rm -f client 
	rm -f server
	rm -f *.o