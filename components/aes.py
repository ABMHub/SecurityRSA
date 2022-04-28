from email import message
from typing import List
from click import FileError
from jsonschema import ValidationError
import numpy as np
from regex import F
from components.keyGen import generateKey
class Aes:
    """ 
        Métodos referentes a cifra AES com chaves de 128 bits e suporte ao modo CTR.
    """
    def __init__(self) -> None:
        self.NUMBER_OF_BYTES = 16
        self.NUMBER_OF_KEYS = 10
        self.key = None
        pass

    def SubBytes(self, state : List[List[bytes]]) -> List[List[bytes]]:
        """ Realiza a transformação não linear da matriz de bytes utilizando a matriz s-box.

        Args:
            state (List[List[bytes]]): matriz de 4x4 bytes de um número de 128 bits

        Raises:
            FileNotFoundError: Arquivo sbox.txt não encontrado

        Returns:
            List[List[bytes]]: Matriz de bytes de 4x4 resultante da transformação não linear.
        """

        sbox = None
        try:
            sbox = np.loadtxt("files/sbox.txt", dtype='str', delimiter=' ')
        except:
            raise FileNotFoundError("Falha ao ler o arquivo sbox.txt")

        for i in range(4):
            for j in range(4):
                ms_nibble = state[i][j] >> 4
                ls_nibble = state[i][j] & 0x0F
                state[i][j] = int(sbox[ms_nibble][ls_nibble], 16)

        return state

    def ShiftRows(self, state : List[List[bytes]]) -> List[List[bytes]]:
        """ Desloca a linha i de state i posições para a esquerda com reposição dos elementos ao final da linha

        Args:
            state (List[List[bytes]]): matriz de 4x4 bytes de um número de 128 bits.

        Returns:
            List[List[bytes]]: state deslocado.
        """
        
        for i in range(4):
            state[i] = np.roll(state[i], -i)

        return state
        
    def MixColumns(self, state : List[List[bytes]]) -> List[List[bytes]]:
        """ Multiplica state pela matriz recomendada

        Args:
            state (List[bytes]): matriz de 4x4 bytes de um número de 128 bits.

        Returns:
            List[List[bytes]]: matriz de 4x4 bytes de um número de 128 bits após multiplicação.

        """
        for i in range(4):
            a = (self.GaloisMultiply(state[0][i], 2) ^ self.GaloisMultiply(state[1][i], 3) ^ self.GaloisMultiply(state[2][i], 1) ^ self.GaloisMultiply(state[3][i], 1))
            b = (self.GaloisMultiply(state[0][i], 1) ^ self.GaloisMultiply(state[1][i], 2) ^ self.GaloisMultiply(state[2][i], 3) ^ self.GaloisMultiply(state[3][i], 1))
            c = (self.GaloisMultiply(state[0][i], 1) ^ self.GaloisMultiply(state[1][i], 1) ^ self.GaloisMultiply(state[2][i], 2) ^ self.GaloisMultiply(state[3][i], 3))
            d = (self.GaloisMultiply(state[0][i], 3) ^ self.GaloisMultiply(state[1][i], 1) ^ self.GaloisMultiply(state[2][i], 1) ^ self.GaloisMultiply(state[3][i], 2))

            state[0][i] = a
            state[1][i] = b
            state[2][i] = c
            state[3][i] = d

        return state

    def AddRoundKey(self, state : List[List[bytes]], round_key : List[List[bytes]]) -> List[List[bytes]]:
        """ Aplica xor elemento a elemento das duas matrizes

        Args:
            state (List[List[bytes]]): matriz de 4x4 bytes de um número de 128 bits.

            round_key (List[List[bytes]]): matriz de 4x4 bytes de um número de 128 bits.

        Returns:
            List[List[bytes]]: matriz de 4x4 bytes de um número de 128 bits.

        """
        
        for i in range(4):
            for j in range(4):
                state[i][j] = state[i][j] ^ round_key[i][j]

        return state

    def GenerateRoundKey(self, key : int, iterations : int = 10) -> List[List[bytes]]:
        """Gera chaves de rodada

        Args:
            key (int): número de 128 bits.

        Returns:
            List[List[List[bytes]]]: Lista de matrizes de 4x4 bytes que representam números de 128 bits.
        """

        bytes_array = key.to_bytes(self.NUMBER_OF_BYTES, 'big')
        bytes_array = np.array(list(bytes_array))
        bytes_array.shape = (4, 4)
        bytes_array = bytes_array.transpose()

        if np.size(bytes_array) != self.NUMBER_OF_BYTES:
            raise ValidationError("AES suporta apenas chaves de 128 bits")

        Rcon = np.zeros(shape=(4, 10), dtype=int)
        Rcon[0] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

        keys = [bytes_array]

        for i in range(1, iterations + 1):
            first_col = keys[i-1][:,0]

            temp = np.roll(keys[i-1], -1, 0)
            last_col_r_sub = self.SubBytes(temp)[:,3]
    
            col0 = np.bitwise_xor(np.bitwise_xor(first_col, last_col_r_sub), Rcon[:,i-1])
            col1 = np.bitwise_xor(col0, keys[i-1][:,1])
            col2 = np.bitwise_xor(col1, keys[i-1][:,2])
            col3 = np.bitwise_xor(col2, keys[i-1][:,3])

            keys.append(np.array([col0, col1, col2, col3]).transpose())

        return np.array(keys)

    def Cipher(self, state : List[List[bytes]], key : int) -> List[List[bytes]]:
        """ Aplica a cifra AES em uma sequência de bytes que correspondem a uma mensagem.

        Args:
            state (List[bytes]): Sequência de bytes que correspondem a mensagem.
            key (int): Chave de 128 bits

        Returns:
            List[bytes]: Sequência de bytes cifrada usando AES
        """

        round_keys = self.GenerateRoundKey(key)
        state = self.AddRoundKey(state, round_keys[0])

        for i in range(self.NUMBER_OF_KEYS - 1):
            state = self.SubBytes(state)
            state = self.ShiftRows(state)
            state = self.MixColumns(state)
            state = self.AddRoundKey(state, round_keys[i+1])

        state = self.SubBytes(state)
        state = self.ShiftRows(state)
        state = self.AddRoundKey(state, round_keys[10])

        return state        

    def ctr():
        pass
    
    def GaloisMultiply(self, a : int, b : int) -> int:
        """Realiza a multiplicação de a por b no corpo de galois.

        Args:
            a (int): fator do produto, 0 <= a <= 255
            b (int): fator do produto, 1 <= b <= 3

        Raises:
            ValueError: a e/ou b não respeitam os intervalos

        Returns:
            int: resultado da multiplicação.
        """
        if a < 0 or b < 0 or a > 256 or b > 3:
            raise ValueError("Multiplicação inválida no corpo de galois!")

        if b == 1: return a
        tmp = (a << 1) & 0x0ff
        if b == 2: return tmp if a < 128 else tmp ^ 0x01b
        if b == 3: return self.GaloisMultiply(a, 2) ^ a