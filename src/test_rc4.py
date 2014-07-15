#!/usr/bin/env python

import sys
import unittest
import rc4

class TestDES(unittest.TestCase):
    def setUp(self):
        self.key1     = 'Key'
        self.plain1   = 'Plaintext'
        self.keyhead1 = 'EB9F7781B734CA72A719'
        self.cipher1  = 'BBF316E8D940AF0AD3'
        self.key2     = 'Wiki'
        self.plain2   = 'pedia'
        self.keyhead2 = '6044DB6D41B7'
        self.cipher2  = '1021BF0420'
        self.key3     = 'Secret'
        self.plain3   = 'Attack at Dawn'
        self.keyhead3 = '04D46B053CA87B59'
        self.cipher3  = '45A01F645FC35B383552544B9BF5'

if __name__ == "__main__":
    unittest.main()
