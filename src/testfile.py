#!/usr/bin/env python

a = '000D2AFBAAEAEFEFAA9CE090C6CE506FFA3'
keystream = []
for number in range(3, 35, 2):  # Keystream calc
    pbyte = int(a[number:number + 2], 16)  # Convert from Hex
    keystream.append(ord('A') ^ pbyte)  # Build keystream
print keystream

key = '000kingand queen'
print [ord(x) for x in key]
