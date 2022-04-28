from components.aes import Aes
from components.rsa import RSA
import hashlib

class TestRSA:
  def test_RSA_Cipher(self):
    rsa = RSA() # passo 1
    aes = Aes() # passo 2
    message = "Como este artigo nos auxiliará: o assunto principal do artigo é justamente o uso de aplicativos para o ensino de linguagens. O foco do artigo gira em torno de linguagens faladas, então nós precisaremos adaptar para uma linguagem de sinais, contudo acreditamos que o modelo que o artigo sugere será útil para termos um norte quanto a como apresentar os exercícios para o usuário. "
    message_hash = hashlib.sha3_256(bytes(RSA.String2IntList(message))).digest() # passo 3

    criptograma = RSA.RSACipherDecipher(list(message_hash), rsa.privateKey) # passo 4
    message_cipher, nonce = aes.CtrCipher(message)
    aes_ciphered_key = rsa.OAEPCipher(rsa.publicKey, aes.key.to_bytes(16, "big"))

    # decipher
    aes.key = rsa.OAEPDecipher(rsa.privateKey, aes_ciphered_key)
    message_decipher = aes.CtrDecipher(message_cipher, nonce)
    new_hash = hashlib.sha3_256(bytes(RSA.String2IntList(message_decipher)))
    message_hash_old = RSA.RSACipherDecipher(criptograma, rsa.publicKey)
    assert new_hash == bytes(message_hash_old)



