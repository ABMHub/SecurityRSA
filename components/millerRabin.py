from secrets import SystemRandom
from components.utils import twoFactors

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
    x = (randNum**d) % n
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
