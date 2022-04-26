from math import log2, floor
from typing import Tuple

BITSTREAM = 16
def twoFactors(n : int, bitNumber : int = BITSTREAM) -> Tuple:
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