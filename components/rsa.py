import numpy as np
from egcd import egcd
from components.keyGen import generateKey, generateE
from typing import Tuple, List
import hashlib
import secrets

class RSA:
  def __init__(self, p_q_keys : Tuple[int, int] = tuple(generateKey(2, 1024))) -> None:
    self.p = p_q_keys[0]
    self.q = p_q_keys[1]
    
    self.n = self.p * self.q
    self.phi = (self.p-1) * (self.q-1)

    self.e = generateE(self.phi)
    out_egcd = egcd(self.e, self.phi)
    self.d = out_egcd[1]

    if self.d < 0: 
      self.d += self.phi

    self.publicKey = (self.n, self.e)
    self.privateKey = (self.n, self.d)

  @staticmethod
  def RSACipherDecipher(input_bytes : List[int], cipherKey : Tuple[int, int]) -> List[int]:
    """Função que cifra ou decifra pelo padrão de RSA. Recebe o input (que é uma lista de bytes) e uma chave de cifra (que pode ser a chave pública ou privada do usuário)

    Args:
        input_bytes (List[bytes]): lista de bytes representando a mensagem ou criptograma
        cipherKey (Tuple[int, int]): chave de cifra, pode ser a chave pública ou privada
    """
    cryptogram = []
    for i in input_bytes:
      cryptogram.append(pow(i, cipherKey[1], cipherKey[0]))

    return cryptogram

  @staticmethod
  def String2IntList(plainText : str) -> bytes:
    """Converte string para bytes

    Args:
        plainText (str): texto string

    Returns:
        bytes: string convertida para um array de bytes da classe "bytes"
    """
    return list(bytes(plainText, 'utf-8'))

  @staticmethod
  def IntList2String(criptogram : bytes) -> str:
    """Converte bytes para string

    Args:
        criptogram (bytes): array de bytes da classe "bytes"

    Returns:
        str: array de bytes convertido para string "str"
    """
    return bytes(criptogram).decode("utf-8")

  import hashlib
  
  def i2osp(self, integer: int, size: int = 4) -> bytes:
    """Converte um inteiro para octetos de bytes.

    Args:
        integer (int): número a ser convertido
        size (int, optional): número de bytes a ser retornado Defaults to 4.

    Returns:
        btyes: bytes do número
    """
    return integer.to_bytes(size, "big")
  
  def mgf1(self, input_str: bytes, length: int, hash_func=hashlib.sha3_256) -> str:
    """Função geradora de máscara. Gera uma máscara 

    Args:
        input_str (bytes): _description_
        length (int): _description_
        hash_func (_type_, optional): _description_. Defaults to hashlib.sha3_256.

    Returns:
        str: _description_
    """
    counter = 0
    output = b""
    while len(output) < length:
        C = self.i2osp(counter, 4)
        output += hash_func(input_str + C).digest()
        counter += 1
    return output[:length]

  def __xorBytes(self, a : bytes, b : bytes) -> bytes:
    assert len(a) == len(b)
    return bytes(c ^ d for c, d in zip(a, b))

  def OAEPCipher(self, cipherKey : Tuple[int, int], message : bytes, label : str = "", seed : int = generateKey(1, 256)[0]) -> bytes:
    """_summary_

    Args:
        publicKey (Tuple[int, int]): _description_
        message (bytes): _description_
        label (str, optional): _description_. Defaults to "".

    Returns:
        bytes: _description_
    """
    k = 256               # tamanho em bytes do módulo rsa (2048 bits)
    hlen = 32             # tamanho do output da hash em bytes
    mlen = len(message)   # tamanho da mensagem em bytes
    if mlen > k - hlen*2 - 2:
      raise ValueError("Message too long")

    label = bytes(RSA.String2IntList(label))
    seed = seed.to_bytes(32, "big")
    lhash = hashlib.sha3_256(label)
    ps = (0).to_bytes(k - mlen - 2*hlen - 2, "big")

    db = lhash.digest() + ps + (1).to_bytes(1, "big") + message
    dbmask = self.mgf1(seed, k-hlen-1)
    maskedDb = self.__xorBytes(db, dbmask)
    seedMask = self.mgf1(maskedDb, hlen)
    maskedSeed = self.__xorBytes(seed, seedMask)

    em = (0).to_bytes(1, "big") + maskedSeed + maskedDb
    print(em)

    return RSA.RSACipherDecipher(list(em), cipherKey)

  def OAEPDecipher(self, cipherKey : Tuple[int, int], cryptogram : bytes, label : str = "") -> bytes:
    k = 256               # tamanho em bytes do módulo rsa (2048 bits)
    hlen = 32             # tamanho do output da hash em bytes
    mlen = len(cryptogram)   # tamanho da mensagem em bytes

    if mlen != k:
      raise ValueError(f"Wrong size for cryptogram. Should be {k}")

    if k < hlen*2 + 2:
      raise ValueError(f"Decryption error")

    label = bytes(RSA.String2IntList(label))
    out = RSA.RSACipherDecipher(list(cryptogram), cipherKey)
    print(out)
    em = bytes(out)

    y = em[0]
    maskedSeed = em[1:hlen+1]
    maskedDb = em[-(k-hlen-1):]

    seedMask = self.mgf1(maskedDb, hlen)
    seed = self.__xorBytes(maskedSeed, seedMask)
    dbMask = self.mgf1(seed, k-hlen-1)
    db = self.__xorBytes(maskedDb, dbMask)

    label_hash = db[:hlen]
    message_padding = db[hlen:]
    flag = False
    for i in range(len(message_padding)):
      if message_padding[i] == 1:
        flag = True
        break

    message = message_padding[i+1:]

    if y != 0:
      raise ValueError("Decryption error!")
    # if label_hash != hashlib.sha3_256(label):
    #   raise ValueError("Decryption error!")
    if flag is False:
      raise ValueError("Decryption error!")

    return message