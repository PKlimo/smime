#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import ctypes
import os

class SMIME_sender:
    def __init__(self):
        lib_path = os.path.dirname(__file__) + "/smime_sender.so"
        self.__lib = ctypes.CDLL(lib_path)
        self.__lib.sign.argtypes = [ctypes.c_char_p]
        self.__lib.sign.restype = ctypes.c_char_p
        self.__lib.encrypt.argtypes = [ctypes.c_char_p]
        self.__lib.encrypt.restype = ctypes.c_char_p

    def sign(self, msg):
        if isinstance(msg, str):
              msg = msg.encode('utf-8')
        data = ctypes.create_string_buffer(msg)
        return self.__lib.sign(data).decode('utf-8')

    def encrypt(self, msg):
        if isinstance(msg, str):
            msg = msg.encode('utf-8')
        data = ctypes.create_string_buffer(msg)
        return self.__lib.encrypt(data).decode('utf-8')
