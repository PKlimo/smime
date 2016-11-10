#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import ctypes
import os

class SMIME_receiver:
    def __init__(self):
        lib_path = os.path.dirname(__file__) + "/smime_receiver.so"
        self.__lib = ctypes.CDLL(lib_path)
        self.__lib.verify.argtypes = [ctypes.c_char_p]
        self.__lib.verify.restype = ctypes.c_char_p
        self.__lib.decrypt.argtypes = [ctypes.c_char_p]
        self.__lib.decrypt.restype = ctypes.c_char_p

    def verify(self, msg):
        if isinstance(msg, str):
              msg = msg.encode('utf-8')
        data = ctypes.create_string_buffer(msg)
        return self.__lib.verify(data).decode('utf-8')

    def decrypt(self, msg):
        if isinstance(msg, str):
            msg = msg.encode('utf-8')
        data = ctypes.create_string_buffer(msg)
        return self.__lib.decrypt(data).decode('utf-8')
