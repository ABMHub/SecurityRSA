import secrets
import hashlib

from components.aes import Aes
from components.keyGen import MillerRabin, generateKey
import numpy as np
from components.rsa import RSA




# message = "Bom dia o dia estaahahahhs"
# print(message)
# rsa = RSA()
# message_bytes = RSA.String2IntList(message)
# out_cipher = RSA.RSACipherDecipher(message_bytes, rsa.publicKey)
# out_decipher = RSA.RSACipherDecipher(out_cipher, rsa.privateKey)
# assert RSA.IntList2String(out_decipher) == message

# correct_result = "TURING"
# result = RSA.IntList2String(RSA.RSACipherDecipher([15, 692, 391, 501, 421, 176], (697, 197)))
# print("Resultado adquirido:", result)
# print("\nResultado esperado:", correct_result)
# assert result == correct_result

# transmissor.applypublickey

# lucas = RSA()
# pedro = RSA()

# pedro.ApplyPublicKey()



# teste = 57811460909138771071931939740208549692 

# correct_result = np.array([
#             [0xa0,0x88,0x23,0x2a],
#             [0xfa,0x54,0xa3,0x6c],
#             [0xfe,0x2c,0x39,0x76],
#             [0x17,0xb1,0x39,0x05],
#             ])

# aes = Aes()
# result = aes.GenerateRoundKey(teste, iterations=2)[1]
# assert np.array_equal(result, correct_result)

from components.rsa import RSA

# rsa = RSA()
# rsa.GenerateKeys()