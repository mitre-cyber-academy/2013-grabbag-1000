#!/usr/bin/env python

import sys
import os
import rc4
import bitarray
import time
import random
import hashlib
import re
import numpy as np

def main():
    print("Initializing....					%s." % time.ctime())
    stime = time.time()  # Timing

    try:
        enc_packets_file = open('encrypted_packets.txt', 'r')
        enc_packets      = enc_packets_file.read().split('\n')
        enc_packets_file.close()
        enc_packets[0]
        print("File Exists, using contents.				%s." % time.ctime())
        for number in range(len(enc_packets)):
            if not re.match('[A-F0-9]+', enc_packets[number]):
                del enc_packets[number]
    except IOError or IndexError:
        print("File Not Found or File Empty. Generating new packets.	%s." % time.ctime())
        packets          = gen_packets()  # Get our encrypted message
        enc_packets      = encrypt_packets(packets)
        packet_file      = open('packets.txt', 'w')
        enc_packets_file = open('encrypted_packets.txt', 'w')
        print("Writing packets to file.				%s." % time.ctime())
        for item in enc_packets:
            enc_packets_file.write('%s\n' % str(item))
        for item in packets:
            packet_file.write('%s\n' % str(item))
        enc_packets_file.close()

    print("Cracking Password.					%s." % time.ctime())
    #password = crack(enc_packets)

    ftime = time.time()
    print('Finished. %f minutes elapsed.' % ((ftime - stime) / 60.0))

def crack(enc_packets):
    '''
    Crack the password
    '''
    count    = 0
    A_matrix = np.zeros((13, len(enc_packets)), dtype=np.uint8)
    print("	Analyzing Packets.				%s." % time.ctime())
    if os.path.isfile('./veryimportantmatrix.npy'):
        A_matrix = np.load('./veryimportantmatrix.npy')
    else:
        for packet in enc_packets:
            src = 'B'
            if count % 2 == 0:
                src = 'A'
            keystream = []
            for number in range(3, 36, 2):  # Keystream calc
                pbyte = int(packet[number:number + 2], 16)  # Convert from Hex
                keystream.append(ord(src) ^ pbyte)  # Build keystream
            packet_analysis(packet, A_matrix[:, count], keystream)
            count += 1
            np.save('veryimportantmatrix', A_matrix)

    '''
    print("	Determing Results				%s." % time.ctime())
    number_of_answers = 2
    frequent_answers = np.zeros((13, number_of_answers), dtype=np.uint8)
    for i in range(13):  # Building a two dimensional array of most frequent_answers
        y = np.bincount(A_matrix[i, :])
        for k in range(number_of_answers):
            index = np.argmax(y)
            frequent_answers[i][k] = y[index]
            y[index] = 0
    print frequent_answers
    def get_Rk(sigma):
        Rk = np.zeros(13, dtype=np.uint8)
        Rk[0] = sigma[0]
        for i in range(1, 13):
            Rk[i] = sigma[i] - sigma[i - 1]
        return Rk
    for j in range(number_of_answers):
        sigma = np.zeros(13, dtype=np.uint8)
        sigma[0] = frequent_answers[0][j]
        for i in range(1, 13):
            sigma[i][j] = frequent_answers[i][j]
        print get_Rk(sigma)
    '''

    print("	Determing Results				%s." % time.ctime())
    sigma = []
    for x in range(13):
        sigma.append(np.argmax(np.bincount(A_matrix[x,:])))
    Rk = np.zeros((13), dtype=np.uint8)
    Rk[0] = sigma[0]
    for i in range(1, 13):
        Rk[i] = ((sigma[i] - sigma[i - 1]))
    print("	Key is %s.				%s." % (str(Rk), time.ctime()))
    print("	Key is %s.				%s." % (str([chr(item) for item in Rk]), time.ctime()))

    for item in enc_packets:
        packet = item[3:]
        key = packet[0:3] + ''.join(str(s) for s in Rk)
        key_array = rc4.key_schedule(key)
        keystream = rc4.get_keyStream(key_array, len(packet))
        print rc4.decrypt(packet, keystream)

def packet_analysis(packet, row, keystream):
    '''
    Analyze given packet
    '''
    S = [x for x in range(256)]  # Create our incremental list
    K = packet[0:3]
    j = 0
    for i in range(3):  # Perform first three rounds of KSA
        j = (j + S[i] + ord(K[i])) % 256
        S[i], S[j] = S[j], S[i]
    for i in range(13):  # Generate A values
        A = get_Fptw(S, j, i, keystream)
        row[i] = A

def get_Fptw(S, j, i, X):
    '''
    Performs the fancy mathematics
    '''
    summed = sum([S[m] for m in range(3, i + 4)])
    S_inv, S_list = compute_inverse(S)
    #ind = i + 3 - X[i + 2]
    #if ind < 0:
    #    ind = 255 - abs(ind)
    #print ind, (i + 3 - X[i + 2]) % 256
    #A = (S_list[ind] - (j + summed))  # Old
    #A = (S_list[i + 3 - X[i + 2]] - (j + summed))  # Old
    ind = np.zeros(1, dtype=np.uint8)
    ind[0] = i + 3 - X[i + 2]
    A = np.zeros(1, dtype=np.uint8)
    A[0] = (S_list[ind[0]] - (j + summed))  # Old
    #A = (S_inv[(i + 3 - X[i + 2]) % 256] - ((j + summed) % 256)) % 256
    #A = (S_inv[(i + 3 - X[i + 2]) % 256] - ((j + summed)))
    #A = (S_list[i + 2 - X[i + 1]] - (sum([S[a] for a in range(3, 4 + i)])))
    return A[0]

def compute_inverse(S):
        '''
        Compte inverse of S
        '''
        S_inv = {}
        for item in S:
            val = S[item]
            S_inv[val] = item
        S_list = [S_inv[item] for item in S_inv]
        return S_inv, S_list

def gen_packets():
    '''
    Generate Plaintext packets for encryption
    '''
    story = list(open('./warandpeace.txt', 'r').read())
    story.insert(723551, 'MCA-C5B2113F')
    story = ''.join(story)
    story = re.sub('[\n\r]{2}', '-', story)
    story = re.sub('[\n\r]', '-', story)
    story_list = [story[x:x + 32] for x in range(0, len(story), 32)]
    packets = []
    count   = 0
    for item in story_list:
        corrupt = (random.randint(0, 9) % 2)
        src = 'B'
        if count % 2 == 0:
            src = 'A'
        if corrupt:
            src = 'Z'
        packet = (16 * src) + gen_string(32)  # Random Strings
        main_contents = (16 * src) + '|' + item + '|'
        pad_length    = 80 - len(main_contents)
        packet        = main_contents + gen_string(pad_length)
        chksum        = packetsum(packet)
        final_packet  = packet + chksum
        packets.append(final_packet)
        count += 1
    return packets

def gen_string(length):
    '''
    Returns a random string with length 64
    '''
    string = ''
    for number in range(length):
        letter = random.randint(97, 122)
        string += chr(letter)
    return string

def encrypt_packets(packets):
    '''
    Encrypt given list of packets
    '''
    count             = 0
    encrypted_packets = []
    flag = 'kingand queen'
    for packet in packets:
        init_vector      = '%03d' % (count % 1000)
        key              = init_vector + flag
        key_array        = rc4.key_schedule(key)
        keystream        = rc4.get_keyStream(key_array, len(packet))
        encrypted_packet = init_vector + rc4.encrypt(packet, keystream)
        encrypted_packets.append(encrypted_packet)
        count += 1
    return encrypted_packets

def packetsum(packet):
    '''
    Return checksum for given packet
    '''
    packetmd5 = hashlib.md5()
    packetmd5.update(packet)
    final = '{0:032X}'.format(int(packetmd5.hexdigest(), 16))
    return final

if __name__ == "__main__":
    sys.exit(main())
