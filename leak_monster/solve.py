#!/usr/bin/env python

import binascii as ba

with open("data") as f:
    data = f.read()

def swap_endianness(block):
    return int.from_bytes(block, "little").to_bytes(4, "big")

flag = b"".join([swap_endianness(ba.unhexlify(block)) for block in data.split()][1:-2])[1:-1].decode()

print(flag)
