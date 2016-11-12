# Basic motivation

The goal of this project is to provide very easy way for working (in python and c) with SMIME messages. To create signed and encrypted smime message:
```python
import sender as snd
sender = snd.SMIME_sender()
msg = "test"
enc = sender.encrypt(sender.sign(msg))
```
to decrypt and verify message:
```python
import receiver as rec
receiver = rec.SMIME_receiver()
dec = receiver.verify(receiver.decrypt(enc))
print(dec)
```
Small script used for testing library is [test.py](test.py)

# Functions in shared library

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

# Make
* `make` (without any arguments):
    * generates certificates `make cert`
    * build sender and receiver (librares and testing programs) `make -C sender` and `make -C receiver`
    * run test - by using testing executables sign, encrypt then decrypt and verify signiture
* `make cert` generate pairs of keys (for signing and encryption)
    * generate files {enc|signer}_{pub|priv}.pem that would be compiled into library / executable
    * these keys can be overwritten and `make` in sender/receiver module creates new `.h` files used in compilation into `.so` librarry
* `make sender/main` and `make receiver/main`  compile libraries `smime_sender.so` and `smime_receiver.so`and executables in directories sender/receiver
    * certificates and clients are transformed into header files (`.h`)
    * shared libraries are compiled (`.so`) for python bindings
    * testing executables are compliled
        * read standard input (string/encrypted message) and print on standard output (encrypted message/decrypted message)
* `make clean` deletes all created files (except source code)
