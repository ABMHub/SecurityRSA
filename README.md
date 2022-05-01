# Gerador de assinaturas RSA e AES

### Dados dos Alunos: 
João Pedro Felix de Almeida, Matrícula: 19/0015292
Lucas de Almeida Bandeira Macedo, Matrícula: 19/0047089

Segurança Computacional TB 2021/2

# Requisitos
O programa foi desenvolvido utilizando a linguagem python versão 3.10.1 e as bibliotecas:

sys: para lidar com linha de comando

numpy: para lidar com diversas manipulações de vetores

pickle: para converter e desconverter objetos em bytes

hashlib: para funções de hash

pytest: para testes unitários

base64: para codificação de bytes em base 64

secrets: para geração de números aleatórios

egcd: para algoritmo de euclides extendido

# Como usar
Trata-se de um programa para ser utilizado via linha de comando, atenção a forma correta de utilizá-lo! 
(Recomendo, se possível, interpretar diretamente no seu computador ao invés de usar o .exe)

É necessário informar a mensagem a ser cifrada/decifrada.

Exemplo de uso: `python assinaturas.py <nome do arquivo da mensagem>.txt`

ou

Exemplo de uso: `python assinaturas.exe <nome do arquivo da mensagem>.txt`

Link do Github: https://github.com/ABMHub/SecurityRSA
