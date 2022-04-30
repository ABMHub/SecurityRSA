import hashlib
from pickle import dumps, loads
import base64
from components.aes import Aes
from components.rsa import RSA
import sys

def help():
    print("Chamada inválida ao programa!")
    print("Exemplo de como usar:")
    print("assinaturas.py (ou assinaturas.exe) <file_name>.txt")
    print("Encerrando...")
    

def main(argv):

    if len(argv) != 1:
        help()
        sys.exit(0)

    with open(argv[0], "r", encoding="utf-8") as f:
      message = f.read()
    # passo 1: par de chaves pública e privada para o RSA
    luscas = RSA() 
    jotape = RSA() 

    # passo 2: chave de sessão para o AES
    aes = Aes()

    # passo 3: calcular o hash da mensagem usando SHA-3
    old_hash = hashlib.sha3_256(bytes(RSA.String2IntList(message))).digest()

    # passo 4: cifrar o hash da mensagem usando a chave privada do RSA
    criptograma = RSA.RSACipherDecipher(list(old_hash), luscas.privateKey)

    # passo 5: cifrar a mensagem usando AES no modo CTR
    message_cipher, nonce = aes.CtrCipher(message)

    # passo 6: aplicar OAEP na chave de sessão do AES
    # passo 7: cifrar o resultado do OAEP com a chave pública do destinatário usando RSA
    key_in_bytes =  aes.key.to_bytes(16, "big")
    aes_ciphered_key = luscas.OAEPCipher(jotape.publicKey, key_in_bytes)

    # passo 8: formatar o resultado (aes_ciphered_key, message_hash, message_cipher, nonce) em base64

    b64_hash_encoded = base64.b64encode(dumps(criptograma))
    b64_message_encoded = base64.b64encode(message_cipher)
    b64_sessionKey_encoded = base64.b64encode(dumps(aes_ciphered_key))

    with open("sessionKey.bin", "wb") as f:
      f.write(b64_sessionKey_encoded)
    with open("message.bin", "wb") as f:
      f.write(b64_message_encoded)
    with open("hash.bin", "wb") as f:
      f.write(b64_hash_encoded)

    with open("hash.bin", "rb") as f:
      b64_hash_decoded = f.read()
    with open("message.bin", "rb") as f:
      b64_message_decoded = f.read()
    with open("sessionKey.bin", "rb") as f:
      b64_sessionKey_decoded = f.read()

    b64_sessionKey_decoded = loads(base64.b64decode(b64_sessionKey_decoded))
    b64_message_decoded = base64.b64decode(b64_message_decoded)
    b64_hash_decoded = loads(base64.b64decode(b64_hash_decoded))

    # passo 9: decifrar a chave de sessão com a chave privada do RSA
    # passo 10: Aplicar a inversa do OAEP e assim obter a chave de sessão
    session_key = jotape.OAEPDecipher(jotape.privateKey, b64_sessionKey_decoded)

    # passo 11: decifrar a assinatura hash usando a chave pública do RSA.
    old_hash_decrypted = RSA.RSACipherDecipher(b64_hash_decoded, luscas.publicKey)

    # passo 12: com a chave de sessão do AES no modo CTR, decifrar a mensagem
    aes.key = int.from_bytes(session_key, 'big')
    message_deciphered = aes.CtrDecipher(b64_message_decoded, nonce)

    # passo 13: calcular o hash da mensagem decifrada (message_deciphered)
    new_hash = hashlib.sha3_256(bytes(message_deciphered, 'utf-8')).digest()

    old_hash_decrypted_bytes = bytes(old_hash_decrypted)
    assert new_hash == old_hash_decrypted_bytes

    print("Mensagem Decifrada:", message_deciphered)

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

    # from components.rsa import RSA

    # rsa = RSA()
    # rsa.GenerateKeys()

if __name__ == '__main__': 
    main(sys.argv[1:])