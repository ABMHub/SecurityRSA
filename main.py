import secrets
import hashlib

from components.aes import Aes
from components.keyGen import MillerRabin, generateKey
import numpy as np

teste = 57811460909138771071931939740208549692 

correct_result = np.array([
            [0xa0,0x88,0x23,0x2a],
            [0xfa,0x54,0xa3,0x6c],
            [0xfe,0x2c,0x39,0x76],
            [0x17,0xb1,0x39,0x05],
            ])

aes = Aes()
result = aes.GenerateRoundKey(teste, iterations=2)[1]
assert np.array_equal(result, correct_result)