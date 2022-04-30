from typing import List, Tuple
from jsonschema import ValidationError
import numpy as np
from components.keyGen import generateKey

class Aes:
    """ 
        Métodos referentes a cifra AES com chaves de 128 bits e suporte ao modo CTR.
    """
    def __init__(self, key : int = generateKey(1, 128)[0]) -> None:
        """_summary_

        Args:
            key (int, optional): Chave do AES. Se não informada, uma key é gerada aleatoriamente generateKey(1, 128)[0].
        """
        self.NUMBER_OF_BYTES = 16
        self.NUMBER_OF_KEYS = 10
        
        try:
            key.to_bytes(self.NUMBER_OF_BYTES, 'big')
        except:
            raise ValidationError("AES suporta apenas chaves de 128 bits")

        self.key = key
        self.nonce_history = {}
        self.sbox =    [[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
                        [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
                        [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
                        [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
                        [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
                        [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
                        [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
                        [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
                        [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
                        [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
                        [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
                        [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
                        [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
                        [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
                        [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
                        [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]]

    def SubBytes(self, state : List[List[bytes]]) -> List[List[bytes]]:
        """ Realiza a transformação não linear da matriz de bytes utilizando a matriz s-box.

        Args:
            state (List[List[bytes]]): matriz de 4x4 bytes de um número de 128 bits

        Raises:
            FileNotFoundError: Arquivo sbox.txt não encontrado

        Returns:
            List[List[bytes]]: Matriz de bytes de 4x4 resultante da transformação não linear.
        """

        for i in range(4):
            for j in range(4):
                ms_nibble = state[i][j] >> 4
                ls_nibble = state[i][j] & 0x0F
                state[i][j] = self.sbox[ms_nibble][ls_nibble]

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

    def __numberToMatrix128(self, number : int) -> List[List[bytes]]:
        """Converte um número de 128 bits para uma matriz de 4x4 bytes

        Args:
            number (int): número de 128 bits

        Returns:
            List[List[bytes]]: matriz de 4x4 bytes
        """

        try:
            bytes_array = number.to_bytes(self.NUMBER_OF_BYTES, 'big')
        except:
            raise ValidationError("AES suporta apenas chaves de 128 bits")

        bytes_array = np.array(list(bytes_array))
        bytes_array.shape = (4, 4)
        bytes_array = bytes_array.transpose()

        return bytes_array

    def GenerateRoundKey(self, key : int, iterations : int = 10) -> List[List[bytes]]:
        """Gera chaves de rodada

        Args:
            key (int): número de 128 bits.

        Returns:
            List[List[List[bytes]]]: Lista de matrizes de 4x4 bytes que representam números de 128 bits.
        """

        bytes_array = self.__numberToMatrix128(key)

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

    def AesCipher(self, state : List[List[bytes]]) -> List[List[bytes]]:
        """ Aplica a cifra AES em uma sequência de bytes que correspondem a uma mensagem.

        Args:
            state (List[List[bytes]]): matriz de 4x4 bytes de um número de 128 bits.

        Returns:
            (List[List[bytes]]): matriz de 4x4 bytes de um número de 128 bits cifrada com AES.
        """

        if state.shape != (4,4):
            raise ValueError("Aes suporta apenas matrizes de 4x4 bytes!")
            
        for i in range(4):
            for j in range(4):
                if state[i][j] > 255:
                    raise ValueError("Aes suporta apenas matrizes de 4x4 bytes!")

        round_keys = self.GenerateRoundKey(self.key)
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

    def CtrCipher(self, plaintext : str, nonce : int = generateKey(1, 96)[0]) -> Tuple[bytes, int]:
        """ Aplica AES no modo CTR em plaintext

        Args:
            plaintext (str, utf8): string que será cifrada
            nonce (int, optional): nonce que será usado na cifragem. Se não for informado, o algoritmo irá gerar um.
        Returns:
            List[List[bytes]]: lista de criptograma em blocos de 128 bits. O último bloco pode ter menos de 128 bits
            int: nonce utilizado durante a cifragem
        """
        
        while nonce in self.nonce_history:
            nonce = generateKey(1, 96)[0]
        
        self.nonce_history[nonce] = True

        ctr_blk = (nonce << 32) + 1

        pt_bytes = np.array(list(bytes(plaintext, 'utf-8')))
        pt = pt_bytes[0 : np.size(pt_bytes) - (np.size(pt_bytes) % 16)]
        pt.shape = (np.size(pt)//16, 16)
        pt_end = pt_bytes[-(np.size(pt_bytes) % 16):]
        
        ct = []

        for i in pt:
            counter_block = self.__numberToMatrix128(ctr_blk)
            ct.append(np.bitwise_xor(i, self.AesCipher(counter_block).transpose().flatten()))
            ctr_blk += 1
        
        if np.size(pt_end) != 128:
            counter_block = self.__numberToMatrix128(ctr_blk)
            trunc_block = self.AesCipher(counter_block).transpose().flatten()[:np.size(pt_end)]
            ct.append(np.bitwise_xor(pt_end, trunc_block))

        ret_bytes = b""

        for i in ct:
            ret_bytes += bytes(list(i))

        return ret_bytes, nonce 

    def CtrDecipher(self, cipher_text : bytes, nonce : int) -> str:
        """ Decifra uma lista de criptogramas em blocos de 128 bits, o último bloco pode ter menos de 128 bits.

        Args:
            cipher_text (btyes): Bytes crus referentes a lista de criptogramas em que cada elemento é um array numpy que contém 128 bits, o último elemento pode ter menos de 128 bits
            nonce (int): nonce utilizado durante a cifragem

        Returns:
            str: texto decifrado
        """
        ctr_blk = (nonce << 32) + 1

        pt = []

        ct_bytes = np.array(list(cipher_text))
        ct = ct_bytes[0 : np.size(ct_bytes) - (np.size(ct_bytes) % 16)]
        ct.shape = (np.size(ct)//16, 16)
        ct_end = ct_bytes[-(np.size(ct_bytes) % 16):]

        for i in ct:
            # i é uma array numpy

            counter_block = self.__numberToMatrix128(ctr_blk)
            pt += list(np.bitwise_xor(i, self.AesCipher(counter_block).transpose().flatten()))
            ctr_blk += 1

        if np.size(ct_end) != 128:
            counter_block = self.__numberToMatrix128(ctr_blk)
            trunc_block = self.AesCipher(counter_block).transpose().flatten()[:np.size(ct_end)]
            pt += list(np.bitwise_xor(ct_end, trunc_block))

        return bytes(pt).decode("utf-8")
    
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
        if a < 0 or b < 0 or a > 255 or b > 3:
            raise ValueError("Multiplicação inválida no corpo de galois!")

        if b == 1: return a
        tmp = (a << 1) & 0x0ff
        if b == 2: return tmp if a < 128 else tmp ^ 0x01b
        if b == 3: return self.GaloisMultiply(a, 2) ^ a