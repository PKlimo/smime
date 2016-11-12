# introduction

This module provide very easy way for working with SMIME messages.
* example for python:
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

msg = "test"

# create signed and encypted message
import sender as snd
sender = snd.SMIME_sender()
enc = sender.encrypt(sender.sign(msg))

# decrypt and verify message
import receiver as rec
receiver = rec.SMIME_receiver()
dec = receiver.verify(receiver.decrypt(enc))

if msg == dec:
    print("Encoding / Decoding succesfull")
else:
    print("Encoding / Decoding error\n")
```

# description

bindings for openssl smime functions (with hard-coded private keys and x509 certificates), that provide functions:
* for sender (`smime_sender.so` for c and module `sender` for python):
    * `char* sign(char* msg)`
        * input: any message as string
        * output: smime signed message
    * `char* encrypt(char* msg)`
        * input: any message as string
        * output: smime enryptd message
* for receiver (`smime_receiver.so` for c and module `receiver` for python):
    * `char* verify(char* msg)`
        * input: smime encoded message
        * output: string extracted from smime message (after successfull verification) or NULL (if verification failed)
    * `char* decrypt(char* msg)`
        * input: smime encrypted message
        * output: string decryped from smime message (after successfull decryption) or NULL (if decryption failed)

note: two modules are necessary, because private keys are hard-coded into library / module, and:
* sender shouldn't contain private key for decryption
* receiver shouldn't contain private key for signing

# instalation
make
* generate pairs of keys (for signing and encryption)
    * `make cert` generates files {enc|signer}_{pub|priv}.pem
    * these keys can be overwritten and `make` in sender/receiver module creates new `.h` files used in compilation into `.so` librarry
* compile libraries `smime_sender.so` and `smime_receiver.so`
