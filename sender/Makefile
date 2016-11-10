CC=gcc
CFLAGS=-std=c99 -Wall -Werror -pedantic -pedantic-errors -Wextra -Wshadow -Wpointer-arith -Wcast-qual \
        -Wstrict-prototypes -Wmissing-prototypes

SOURCES=sender.c
OBJECTS=$(SOURCES:.c=.o)

all: main lib

clean:
	rm -f $(OBJECTS)
	rm -f main
	rm -f smime_sender.so
	rm -f signer_priv.h
	rm -f enc_pub.h
	rm -rf __pycache__/

%.o: %.c signer_priv.h enc_pub.h
	$(CC) -c $(CFLAGS) $< -o $@

signer_priv.h: signer_priv.pem
	xxd -i signer_priv.pem > signer_priv.h

enc_pub.h: enc_pub.pem
	xxd -i enc_pub.pem > enc_pub.h

main: $(OBJECTS)
	$(CC) -o main -lssl -lcrypto $(OBJECTS)

lib: $(OBJECTS)
	$(CC) -fPIC -shared -lssl -lcrypto -o smime_sender.so $(OBJECTS)
