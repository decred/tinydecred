"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import unittest

from tinydecred.crypto import mnemonic
from tinydecred.util.encode import ByteArray


class TestMnemonic(unittest.TestCase):
    def test_all(self):
        # fmt: off
        tests = [
            (
                "topmost Istanbul Pluto vagabond treadmill Pacific brackish dictator"
                " goldfish Medusa afflict bravado chatter revolver Dupont midsummer stopwatch"
                " whimsical cowbell bottomless",
                ByteArray([
                    0xE5, 0x82, 0x94, 0xF2, 0xE9, 0xA2, 0x27, 0x48,
                    0x6E, 0x8B, 0x06, 0x1B, 0x31, 0xCC, 0x52, 0x8F, 0xD7,
                    0xFA, 0x3F, 0x19
                ]),
            ),
            (
                "stairway souvenir flytrap recipe adrift upcoming artist positive"
                " spearhead Pandora spaniel stupendous tonic concurrent transit Wichita lockup"
                " visitor flagpole escapade",
                ByteArray([
                    0xD1, 0xD4, 0x64, 0xC0, 0x04, 0xF0, 0x0F, 0xB5,
                    0xC9, 0xA4, 0xC8, 0xD8, 0xE4, 0x33, 0xE7, 0xFB, 0x7F,
                    0xF5, 0x62, 0x56
                ]),
            ),
        ]
        # fmt: on
        listToLower = lambda l: [x.lower() for x in l]
        for i, (words, seed) in enumerate(tests):
            unWords = mnemonic.encode(seed)
            self.assertListEqual(
                listToLower(unWords[: len(unWords) - 1]), listToLower(words.split())
            )
            unSeed = mnemonic.decode(words.split())
            self.assertEqual(seed, unSeed)

    def test_bad_paths(self):
        words = ["", "meme"]
        self.assertRaises(Exception, mnemonic.decode, words)
        words = ["acme", "kiwi"]
        self.assertRaises(Exception, mnemonic.decode, words)
