COMP = gcc
COMPFLAGS = -Wall -Werror

dev: clean client server

all: client server 

client: client.o
	$(COMP) -o client client.o

server: server.o
	$(COMP) -o server server.o -lldap -lssl -lcrypto

client.o: client.c
	$(COMP) $(COMPFLAGS) -c client.c

server.o: server.c
	$(COMP) $(COMPFLAGS) -c server.c

clean:
	rm -f client client.o
	rm -f server server.o
