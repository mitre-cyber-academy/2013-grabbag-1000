#!/usr/bin/env python

import sys
import rc4
import pp
import des

jobServer = pp.Server()
jobs = []

print 'Using %i Workers' % jobServer.get_ncpus()

def main():
    key = 'mitre'
    message = 'the quick brown fox lept over the lazy dog'
    key_array = rc4.key_schedule(key)
    keystream = rc4.get_keyStream(key_array, len(message))
    ciphertext = rc4.encrypt(message, keystream)
    outfile = open('out.txt', 'w')
    alphabet = [chr(x) for x in range(97, 123)]
    for l1 in alphabet:
        print l1,
        for l2 in alphabet:
            for l3 in alphabet:
                for l4 in alphabet:
                    for l5 in alphabet:
                        key = l1 + l2 + l3 + l4 + l5
                        jobs.append(
                                jobServer.submit(try_combo,
                                                (key, ciphertext, outfile),
                                                (decrypt, key_schedule, get_keyStream))
                                )
    print('Jobs added. Completing Jobs')
    for job in jobs:
        job()
    jobServer.get_stats()
    jobServer.print_stats()

def try_combo(key, ciphertext, outfile):
    kyarray = key_schedule(key)
    dkstrm = get_keyStream(kyarray, len(ciphertext) / 2)

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
        j                          = (j + key_array[i] + ord(key[i % len(key)])) % 256
        key_array[i], key_array[j] = key_array[j], key_array[i]
    return key_array


if __name__ == "__main__":
    sys.exit(main())
