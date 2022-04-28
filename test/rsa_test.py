from components.rsa import RSA

class TestRSA:
  def test_RSA_Cipher(self):
    correct_result = [33, 612, 328, 360, 674, 403]
    result = RSA.RSACipherDecipher(RSA.String2IntList("TURING"), (697, 13))
    print("Resultado adquirido:", result)
    print("\nResultado esperado:", correct_result)
    assert result == correct_result

  def test_RSA_Decipher(self):
    correct_result = "TURING"
    result = RSA.IntList2String(RSA.RSACipherDecipher([33, 612, 328, 360, 674, 403], (697, 197)))
    print("Resultado adquirido:", result)
    print("\nResultado esperado:", correct_result)
    assert result == correct_result

  def test_RSA_Public_Private(self):
    message = "Como este artigo nos auxiliará: o assunto principal do artigo é justamente o uso de aplicativos para o ensino de linguagens. O foco do artigo gira em torno de linguagens faladas, então nós precisaremos adaptar para uma linguagem de sinais, contudo acreditamos que o modelo que o artigo sugere será útil para termos um norte quanto a como apresentar os exercícios para o usuário. "
    message_bytes = RSA.String2IntList(message)
    out_cipher = RSA.RSACipherDecipher(message_bytes, (697, 13))
    out_decipher = RSA.RSACipherDecipher(out_cipher, (697, 197))
    assert RSA.IntList2String(out_decipher) == message

  def test_RSA_Private_Public(self):
    message = "Como este artigo nos auxiliará: o assunto principal do artigo é justamente o uso de aplicativos para o ensino de linguagens. O foco do artigo gira em torno de linguagens faladas, então nós precisaremos adaptar para uma linguagem de sinais, contudo acreditamos que o modelo que o artigo sugere será útil para termos um norte quanto a como apresentar os exercícios para o usuário. "
    message_bytes = RSA.String2IntList(message)
    out_cipher = RSA.RSACipherDecipher(message_bytes, (697, 197))
    out_decipher = RSA.RSACipherDecipher(out_cipher, (697, 13))
    assert RSA.IntList2String(out_decipher) == message

  def test_RSA_RandomKeys(self):
    message = "Como este artigo nos auxiliará: o assunto principal do artigo é justamente o uso de aplicativos para o ensino de linguagens. O foco do artigo gira em torno de linguagens faladas, então nós precisaremos adaptar para uma linguagem de sinais, contudo acreditamos que o modelo que o artigo sugere será útil para termos um norte quanto a como apresentar os exercícios para o usuário. "
    print(message)
    rsa = RSA()
    message_bytes = RSA.String2IntList(message)
    out_cipher = RSA.RSACipherDecipher(message_bytes, rsa.publicKey)
    out_decipher = RSA.RSACipherDecipher(out_cipher, rsa.privateKey)
    assert RSA.IntList2String(out_decipher) == message

  def test_RSA_RandomKeys2(self):
    message = "Como este artigo nos auxiliará: o assunto principal do artigo é justamente o uso de aplicativos para o ensino de linguagens. O foco do artigo gira em torno de linguagens faladas, então nós precisaremos adaptar para uma linguagem de sinais, contudo acreditamos que o modelo que o artigo sugere será útil para termos um norte quanto a como apresentar os exercícios para o usuário. "
    print(message)
    rsa = RSA()
    message_bytes = RSA.String2IntList(message)
    out_cipher = RSA.RSACipherDecipher(message_bytes, rsa.privateKey)
    out_decipher = RSA.RSACipherDecipher(out_cipher, rsa.publicKey)
    assert RSA.IntList2String(out_decipher) == message    

  def test_OAEP(self):
    message = "Turing"
    rsa = RSA()
    out_cip = rsa.OAEPCipher((697, 13), bytes(RSA.String2IntList(message)))
    out_dec = rsa.OAEPDecipher((697, 197), out_cip)
    print("teste", out_dec)
    result = RSA.IntList2String(list(out_dec))
    assert message == result

  def test_OAEP2(self):
    message = "Turing"
    rsa = RSA()
    out_cip = rsa.OAEPCipher(rsa.publicKey, bytes(RSA.String2IntList(message)))
    out_dec = rsa.OAEPDecipher(rsa.privateKey, out_cip)
    print("teste", out_dec)
    result = RSA.IntList2String(list(out_dec))
    assert message == result
