CC=gcc
CFLAGS=-std=c99 -Wall -Werror -pedantic -pedantic-errors -Wextra -Wshadow -Wpointer-arith -Wcast-qual \
        -Wstrict-prototypes -Wmissing-prototypes

SOURCES=receiver.c
OBJECTS=$(SOURCES:.c=.o)

all: main lib

clean:
	rm -f $(OBJECTS)
	rm -f main
	rm -f smime_receiver.so
	rm -f signer_pub.h
	rm -f enc_priv.h
	rm -rf __pycache__/

%.o: %.c signer_pub.h enc_priv.h
	$(CC) -c $(CFLAGS) $< -o $@

signer_pub.h: signer_pub.pem
	xxd -i signer_pub.pem > signer_pub.h

enc_priv.h: enc_priv.pem
	xxd -i enc_priv.pem > enc_priv.h

main: $(OBJECTS)
	$(CC) -o main -lssl -lcrypto $(OBJECTS)

lib: $(OBJECTS)
	$(CC) -fPIC -shared -lssl -lcrypto -o smime_receiver.so $(OBJECTS)
