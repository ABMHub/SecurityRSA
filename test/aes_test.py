from wsgiref.util import shift_path_info
from components.aes import Aes
import numpy as np

class TestAes:
    def test_ShiftRows(self):
        teste = np.array([[1, 2, 3, 4],
                        [5, 6, 7, 8 ],
                        [9, 10, 11, 12],
                        [13, 14, 15, 16]])

        correct_result = np.array([[1, 2, 3, 4],
                        [ 6, 7, 8, 5],
                        [11, 12, 9, 10],
                        [16, 13, 14, 15]])

        aes = Aes()
        result = aes.ShiftRows(teste)
        assert np.array_equal(result, correct_result)

    def test_SubBytes(self):
        teste = np.array([
                [0x19, 0xA0, 0x9A, 0xE9],
                [0x3D, 0xF4, 0xC6, 0xF8],
                [0xE3, 0xE2, 0x8D, 0x48],
                [0xBE, 0x2B, 0x2A, 0x08],
                ])

        correct_result = np.array([
                [0xD4, 0xE0, 0xB8, 0x1E],
                [0x27, 0xBF, 0xB4, 0x41],
                [0x11, 0x98, 0x5D, 0x52],
                [0xAE, 0xF1, 0xE5, 0x30],
                ])
        
        aes = Aes()
        result = aes.SubBytes(teste)
        print("Resultado", result)
        print("\nCorreto", correct_result)
        assert np.array_equal(result, correct_result)
