from components.keyGen import MillerRabin, twoFactors, generateKey

class TestKeyGen:
  def test_twoFactors(self):
    assert twoFactors(32) == (5, 1)
    assert twoFactors(33) == (0, 33)
    assert twoFactors(2) == (1, 1)
    assert twoFactors(16) == (4, 1)
    assert twoFactors(17) == (0, 17)
    assert twoFactors(18) == (1, 9)
    assert twoFactors(20) == (2, 5)

  def test_MillerRabinPrime(self):
    assert MillerRabin(421, 1000) == True
    assert MillerRabin(3323, 1000) == True
    assert MillerRabin(1667, 1000) == True
    assert MillerRabin(2441, 1000) == True
    assert MillerRabin(3319, 1000) == True
    assert MillerRabin(4001, 1000) == True
    assert MillerRabin(5171, 1000) == True
    assert MillerRabin(6599, 1000) == True
    assert MillerRabin(7129, 1000) == True
    assert MillerRabin(7583, 1000) == True
    assert MillerRabin(7919, 1000) == True

  def test_MillerRabinCompost(self):
    assert MillerRabin(3333, 1000) == False
    assert MillerRabin(3519, 1000) == False
    assert MillerRabin(3771, 1000) == False
    assert MillerRabin(4113, 1000) == False
    assert MillerRabin(4653, 1000) == False
    assert MillerRabin(4879, 1000) == False
    assert MillerRabin(4907, 1000) == False
    assert MillerRabin(5055, 1000) == False
    assert MillerRabin(6000, 1000) == False
    assert MillerRabin(2012, 1000) == False
    assert MillerRabin(54684, 1000) == False
    assert MillerRabin(31416, 1000) == False
    assert MillerRabin(431698, 1000) == False

  