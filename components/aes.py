from typing import List
from click import FileError
from jsonschema import ValidationError
import numpy as np
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
        

    def MixColumns(self, state):
        pass

    def AddRoundKey(self, state, round_key):
        pass

    def GenerateRoundKey(self, key : List[bytes]) -> List[List[bytes]]:
        """ Gera as chaves de rodada

        Args:
            key (List[bytes]): Chave inicial

        Returns:
            List[List[bytes]]: Lista contendo self.NUMBER_OF_KEYS (10) chaves
        """
        pass

    def cipher(self, state : List[bytes], key : int) -> List[bytes]:
        """ Aplica a cifra AES em uma sequência de bytes que correspondem a uma mensagem.

        Args:
            state (List[bytes]): Sequência de bytes que correspondem a mensagem.
            key (int): Chave de 128 bits

        Returns:
            List[bytes]: Sequência de bytes cifrada usando AES
        """

        bytes_array = key.to_bytes(self.NUMBER_OF_BYTES, 'big')
        bytes_array = np.array(list(bytes_array))
        bytes_array.shape = (4, 4)
        bytes_array.transpose()

        if np.size(bytes_array) != self.NUMBER_OF_BYTES:
            raise ValidationError("AES suporta apenas chaves de 128 bits")

        round_keys = self.GenerateRoundKey(key)

        for i in range(self.NUMBER_OF_KEYS - 1):
            state = self.SubBytes(state)
            state = self.ShiftRows(state)
            state = self.MixColumns(state)
            state = self.AddRoundKey(state, round_keys[i])

        state = self.SubBytes(state)
        state = self.ShiftRows(state)
        state = self.AddRoundKey(state, round_keys[i])

        return state        

    def ctr():
        pass
    