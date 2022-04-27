import secrets
import hashlib

from components.aes import Aes
from components.keyGen import MillerRabin, generateKey
import numpy as np

teste = np.array([
                ["19", "A0", "9A", "E9"],
                ["3D", "F4", "C6", "F8"],
                ["E3", "E2", "82", "48"],
                ["BE", "2B", "2A", "08"],
                ])

correct_result = np.array([
    ["D4", "E0", "B8", "1E"],
    ["27", "BF", "B4", "41"],
    ["11", "98", "5D", "52"],
    ["AE", "F1", "E5", "30"],
    ])

for i in range(4):
    for j in range(4):
        teste[i][j] = int(teste[i][j], 16)
        correct_result[i][j] = int(correct_result[i][j], 16)

aes = Aes()
result = aes.SubBytes(teste)
assert np.array_equal(result, correct_result)
# hashlib.sha3_256("a")

# print(generateKey(2))



# num = secrets.randbits(32) # i2osp

# print(num.to_bytes(4, "big"))

# num8 = format(num, "256")
# num10 = int(num8, 256)
# print(num == num10)
# base256 = num.to_bytes((num.bit_length()+7)//8, 'big')
# print(256**128 == 2**1024)
# number =int.from_bytes(base256, 'big')
# print(base256[0])
# num = secrets.randbits(1024)
# num8 = format(num, "256")
# num10 = int(num8, 256)
# print(num == num10)

# print(secrets.randbits(1024))
# print(utils.twoFactors(41))