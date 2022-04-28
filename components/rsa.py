import numpy as np
from egcd import egcd
from components.keyGen import generateKey, generateE
from typing import Tuple, List

class RSA:
  def __init__(self, p_q_keys : Tuple[int, int] = tuple(generateKey(2, 1024))) -> None:
    self.p = p_q_keys[0]
    self.q = p_q_keys[1]
    
    self.n = self.p * self.q
    self.phi = (self.p-1) * (self.q-1)

    self.e = generateE(self.phi)
    self.d = egcd(self.e, self.phi)[1]

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
