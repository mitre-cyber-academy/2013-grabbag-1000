#!/usr/bin/env python

import sys
import argparse
import bitarray

def main():
    args      = get_args()
    key_array = key_schedule(args.key)
    if args.decrypt:
        keystream = get_keyStream(key_array, len(args.message) / 2)
        final     = decrypt(args.message, keystream)
    else:
        keystream = get_keyStream(key_array, len(args.message))
        final     = encrypt(args.message, keystream)
    print final

def encrypt(message, keystream):
    '''
    XOR encrypt
    '''
    message_list = list(message)
    final = ''
    for number in range(len(message)):
        character = ord(message_list[number])
        keynum    = keystream[number]
        append_string = "{0:0{1}X}".format(character ^ keynum, 2)
        final += append_string
    return final

def decrypt(message, keystream):
    '''
    XOR decrypt
    '''
    message_list = [message[x:x + 2] for x in range(0, len(message), 2)]
    final = ''
    for number in range(len(message_list)):
        character = int(message_list[number], 16)
        keynum    = keystream[number]
        append_string = chr(character ^ keynum)
        final += append_string
    return final

def get_keyStream(key_array, length):
    '''
    Generates the keystream
    :param array[int]: key_array
    '''
    i         = j = 0
    keystream = []
    for number in range(length):
        i                          = (i + 1) % 256
        j                          = (j + key_array[i]) % 256
        key_array[i], key_array[j] = key_array[j], key_array[i]
        k                          = key_array[(key_array[i] + key_array[j]) % 256]
        keystream.append(k)
    return keystream

def key_schedule(key):
    '''
    Performs the key schedule algorithm
    :param string: key
    '''
    key_array = []
    for i in range(256):
        key_array.append(i)
    j = 0
    for i in range(256):
        j = (j + key_array[i] + ord(key[i % len(key)])) % 256
        key_array[i], key_array[j] = key_array[j], key_array[i]
    return key_array


def get_args():
    default = '''the quick BROWN fox lept OVER\
    the lazy DOG_1234568790=_=-=_+_+\][|}{~`!@#$%^&*():/.,?><'''
    parser = argparse.ArgumentParser()
    parser.add_argument('-m', '--message', type=str,
                        default=default, help='Input Message')
    parser.add_argument('-d', '--decrypt', action='store_true',
                        help='Decrypt?')
    parser.add_argument('-e', '--encrypt', action='store_true',
                        help='Encrypt?')
    parser.add_argument('-f', '--fileinput', type=str,
                        default=None, help='Input File')
    parser.add_argument('-k', '--key', type=str,
                        default='king', help='Key')
    args = parser.parse_args()
    if args.fileinput:
        args.message = open(args.fileinput, 'r').read()[:-1]
    return args

if __name__=="__main__":
    sys.exit(main())
