import secrets
import hashlib
# import Integer

from components.keyGen import MillerRabin, generateKey

# hashlib.sha3_256("a")

# print(generateKey(2))



num = secrets.randbits(32) # i2osp

print(num.to_bytes(4, "big"))

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