from components.aes import Aes
from components.rsa import RSA
import hashlib

class TestRSA:
    def test_all_together(self):
        # passo 1: par de chaves pública e privada para o RSA
        rsa = RSA() 

        # passo 2: chave de sessão para o AES
        aes = Aes()

        # passo 3: calcular o hash da mensagem usando SHA-3
        message = "Como este artigo nos auxiliará: o assunto principal do artigo é justamente o uso de aplicativos para o ensino de linguagens. O foco do artigo gira em torno de linguagens faladas, então nós precisaremos adaptar para uma linguagem de sinais, contudo acreditamos que o modelo que o artigo sugere será útil para termos um norte quanto a como apresentar os exercícios para o usuário. "
        old_hash = hashlib.sha3_256(bytes(RSA.String2IntList(message))).digest()

        # passo 4: cifrar o hash da mensagem usando a chave privada do RSA
        criptograma = RSA.RSACipherDecipher(list(old_hash), rsa.privateKey) # passo 4

        # passo 5: cifrar a mensagem usando AES no modo CTR
        message_cipher, nonce = aes.CtrCipher(message)

        # passo 6: aplicar OAEP na chave de sessão do AES
        # passo 7: cifrar o resultado do OAEP com a chave pública do destinatário usando RSA
        key_in_bytes =  aes.key.to_bytes(16, "big")
        aes_ciphered_key = rsa.OAEPCipher(rsa.publicKey, key_in_bytes)

        # passo 8: formatar o resultado (aes_ciphered_key, message_hash, message_cipher, nonce) em base64

        # decipher

        # passo 9: decifrar a chave de sessão com a chave privada do RSA
        # passo 10: Aplicar a inversa do OAEP e assim obter a chave de sessão
        session_key = rsa.OAEPDecipher(rsa.privateKey, aes_ciphered_key)

        # passo 11: decifrar a assinatura hash usando a chave pública do RSA.
        old_hash_decrypted = RSA.RSACipherDecipher(criptograma, rsa.publicKey)

        # passo 12: com a chave de sessão do AES no modo CTR, decifrar a mensagem
        aes.key = int.from_bytes(session_key, 'big')
        message_deciphered = aes.CtrDecipher(message_cipher, nonce)

        # passo 13: calcular o hash da mensagem decifrada (message_deciphered)
        new_hash = hashlib.sha3_256(bytes(message_deciphered, 'utf-8')).digest()

        old_hash_decrypted_bytes = bytes(old_hash_decrypted)
        assert new_hash == old_hash_decrypted_bytes

    def test_all_together_with_label(self):
        # passo 1: par de chaves pública e privada para o RSA
        rsa = RSA() 

        # passo 2: chave de sessão para o AES
        aes = Aes()

        # passo 3: calcular o hash da mensagem usando SHA-3
        message = "Como este artigo nos auxiliará: o assunto principal do artigo é justamente o uso de aplicativos para o ensino de linguagens. O foco do artigo gira em torno de linguagens faladas, então nós precisaremos adaptar para uma linguagem de sinais, contudo acreditamos que o modelo que o artigo sugere será útil para termos um norte quanto a como apresentar os exercícios para o usuário. "
        old_hash = hashlib.sha3_256(bytes(RSA.String2IntList(message))).digest()

        # passo 4: cifrar o hash da mensagem usando a chave privada do RSA
        criptograma = RSA.RSACipherDecipher(list(old_hash), rsa.privateKey) # passo 4

        # passo 5: cifrar a mensagem usando AES no modo CTR
        message_cipher, nonce = aes.CtrCipher(message)

        # passo 6: aplicar OAEP na chave de sessão do AES
        # passo 7: cifrar o resultado do OAEP com a chave pública do destinatário usando RSA
        key_in_bytes =  aes.key.to_bytes(16, "big")
        aes_ciphered_key = rsa.OAEPCipher(rsa.publicKey, key_in_bytes, label="Ola Mundo")

        # passo 8: formatar o resultado (aes_ciphered_key, message_hash, message_cipher, nonce) em base64

        # decipher

        # passo 9: decifrar a chave de sessão com a chave privada do RSA
        # passo 10: Aplicar a inversa do OAEP e assim obter a chave de sessão
        session_key = rsa.OAEPDecipher(rsa.privateKey, aes_ciphered_key, label="Ola Mundo")

        # passo 11: decifrar a assinatura hash usando a chave pública do RSA.
        old_hash_decrypted = RSA.RSACipherDecipher(criptograma, rsa.publicKey)

        # passo 12: com a chave de sessão do AES no modo CTR, decifrar a mensagem
        aes.key = int.from_bytes(session_key, 'big')
        message_deciphered = aes.CtrDecipher(message_cipher, nonce)

        # passo 13: calcular o hash da mensagem decifrada (message_deciphered)
        new_hash = hashlib.sha3_256(bytes(message_deciphered, 'utf-8')).digest()

        old_hash_decrypted_bytes = bytes(old_hash_decrypted)
        assert new_hash == old_hash_decrypted_bytes



