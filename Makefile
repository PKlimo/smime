test: build
	echo "test message\nwith more lines" | ./sender/main | ./receiver/main

build: cert sender/main receiver/main

cert: sender/enc_pub.pem receiver/enc_priv.pem sender/signer_priv.pem receiver/signer_pub.pem

sender/signer_priv.pem receiver/signer_pub.pem:
	openssl req -newkey rsa:2048 -nodes -sha256 -keyout signer_priv.pem -out signer_pub.pem -subj "/C=GB/ST=London/L=London/O=Global Security/OU=IT Department/CN=example.com"
	openssl x509 -req -in signer_pub.pem -signkey signer_priv.pem -out cert.pem -sha256 -days 3650
	cat cert.pem >> signer_priv.pem
	mv cert.pem signer_pub.pem
	mkdir -p sender
	mkdir -p receiver
	mv signer_priv.pem sender/
	mv signer_pub.pem receiver/

receiver/enc_priv.pem sender/enc_pub.pem:
	openssl req -newkey rsa:2048 -nodes -sha256 -keyout enc_priv.pem -out enc_pub.pem -subj "/C=GB/ST=London/L=London/O=Global Security/OU=IT Department/CN=example.com"
	openssl x509 -req -in enc_pub.pem -signkey enc_priv.pem -out cert.pem -sha256 -days 3650
	cat cert.pem >> enc_priv.pem
	mv cert.pem enc_pub.pem
	mkdir -p sender
	mkdir -p receiver
	mv enc_pub.pem sender/
	mv enc_priv.pem receiver/

sender/main:
	$(MAKE) -C sender

receiver/main:
	$(MAKE) -C receiver

clean:
	$(MAKE) -C sender clean
	$(MAKE) -C receiver clean
	rm -f sender/enc_pub.pem
	rm -f sender/signer_priv.pem
	rm -f receiver/signer_pub.pem
	rm -f receiver/enc_priv.pem
	rm -f receiver/enc_pub.pem
