from secrets import SystemRandom
from typing import List
from typing import Tuple
import secrets
from math import gcd

BITSTREAM = 16
def twoFactors(n : int, bitNumber : int = BITSTREAM) -> Tuple[int, int]:
  """Função que calcula o número de fatores de 2 em determinado número

  Args:
      n (int): número a descobrir o número de fatores de 2
      bitNumber (int, optional): número de bits. Defaults to BITSTREAM.

  Returns:
      tuple(int, int): retorna (r, d) tal que n = 2^r * d
  """
  bit_str = "0" + str(bitNumber) + "b"
  bits = f'{n:{bit_str}}'
  two_factors = 0

  for bit in range(len(bits)-1, -1, -1):
    if bits[bit] == '1': 
      break
    two_factors += 1

  return (two_factors, int(bits[0:bit+1],2))

def MillerRabin(n : int, k : int) -> bool:
  """Aponta se um número é provavelmente primo ou não

  Args:
      n (int): n maior que 3
      k (int): número de testes

  Returns:
      bool: True se for provavelmente primo, False se não
  """
  if n % 2 == 0:
    return False

  r, d = twoFactors(n-1)

  if (2**r) * d + 1 != n:
    raise ValueError("2^r * d + 1 != n")
  if d % 2 == 0:
    raise ValueError("d não é ímpar")

  for i in range(k):
    continue_flag = False
    randNum = SystemRandom().randrange(2, n-2)

    x = pow(randNum, d, n)
    if x == 1 or x == n-1:
      continue

    for j in range(r-1):
      x = (x**2) % n

      if x == n-1:
        continue_flag = True
        break

    if continue_flag is True:
      continue
    return False
  return True

def generateKey(k : int = 2, key_length : int = 1024) -> List[int]:
  """Retorna uma lista com k primos aleatórios de 1024 bits

  Args:
      k (int, optional): número de primos aleatórios a retornar. Defaults to 2.

  Returns:
      List[int]: lista com k primos aleatório de 1024 bits
  """
  ret = []
  num = 0
  for i in range(k):
    flag = False
    while flag is False:
      num = secrets.randbits(key_length)
      flag = MillerRabin(num, 10)
      # evita que retorne dois numeros iguais
      if flag is True and num in ret and num >> 1023 != 1:
        flag = False
      
    ret.append(num)
  return ret

def generateE(maxValue : int) -> int:
  """Gera um número no máximo "maxValue" e maior que 1024 bits

  Args:
      maxValue (int): teto para a geração do número primo

  Returns:
      int: número primo aleatório menor que "maxValue" e coprimo deste
  """
  flag = False
  while flag is False:
    num = secrets.randbelow(maxValue)
    if num >> 1024 > 0:   # tem que ser maior que p ou q
      flag = True         # sai do loop e retorna num

  return num
      
