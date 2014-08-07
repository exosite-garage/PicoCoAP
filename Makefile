CC=gcc
IDIR=src
OPT:=-Wall -pedantic -std=c99 -g

all: test release

release: src/coap.c
	$(CC) $(OPT) -Os -c src/coap.c -o picocoap.o

debug: src/coap.c
	$(CC) $(OPT) -c src/coap.c -o picocoap.o

test: tests/coap_test.c src/coap.h
	$(CC) $(OPT) tests/coap_test.c src/coap.c -o test
	./test
	rm test

buildtest: tests/coap_test.c src/coap.h
	$(CC) $(OPT) tests/coap_test.c src/coap.c -o test

posixclient: examples/posix/client.c src/coap.h
	$(CC) $(OPT) -D_POSIX_SOURCE examples/posix/client.c src/coap.c -o posixclient

posixclientd: examples/posix/client_dtls.c src/coap.h
	$(CC) $(OPT) -D_POSIX_SOURCE examples/posix/client_dtls.c src/coap.c -o posixclientd

clean:
	rm -f picocoap.o
	rm -f test
	rm -f posixclient
	rm -f posixclientd
