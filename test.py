#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sender as snd
import receiver as rec

if __name__ == "__main__":
    msg = "test"

    sender = snd.SMIME_sender()
    receiver = rec.SMIME_receiver()

    enc = sender.encrypt(sender.sign(msg))
    dec = receiver.verify(receiver.decrypt(enc))

    if msg == dec:
        print("Encoding / Decoding succesfull")
        print("Data:", dec)
    else:
        print("Encoding / Decoding error\n")
        print("Original data:", msg)
        print("Decoded data:", dec)
