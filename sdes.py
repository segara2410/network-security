#!/usr/bin/python3
#
# Author: Joao H de A Franco (jhafranco@acm.org)
#
# Description: Simplified DES implementation in Python 3
#
# Date: 2012-02-10
#
# License: Attribution-NonCommercial-ShareAlike 3.0 Unported
#          (CC BY-NC-SA 3.0)
#===========================================================
from sys import exit
from time import time

KeyLength = 10
SubKeyLength = 8
DataLength = 8
FLength = 4

# Tables for initial and final permutations (b1, b2, b3, ... b8)
IPtable = (2, 6, 3, 1, 4, 8, 5, 7)
FPtable = (4, 1, 3, 5, 7, 2, 8, 6)

# Tables for subkey generation (k1, k2, k3, ... k10)
P10table = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8table = (6, 3, 7, 4, 8, 5, 10, 9)

# Tables for the fk function
EPtable = (4, 1, 2, 3, 2, 3, 4, 1)
S0table = (1, 0, 3, 2, 3, 2, 1, 0, 0, 2, 1, 3, 3, 1, 3, 2)
S1table = (0, 1, 2, 3, 2, 0, 1, 3, 3, 0, 1, 0, 2, 1, 0, 3)
P4table = (2, 4, 3, 1)

def perm(inputByte, permTable):
    """Permute input byte according to permutation table"""
    outputByte = 0
    for index, elem in enumerate(permTable):
        if index >= elem:
            outputByte |= (inputByte & (128 >> (elem - 1))) >> (index - (elem - 1))
        else:
            outputByte |= (inputByte & (128 >> (elem - 1))) << ((elem - 1) - index)
    return outputByte

def ip(inputByte):
    """Perform the initial permutation on data"""
    return perm(inputByte, IPtable)

def fp(inputByte):
    """Perform the final permutation on data"""
    return perm(inputByte, FPtable)

def swapNibbles(inputByte):
    """Swap the two nibbles of data"""
    return (inputByte << 4 | inputByte >> 4) & 0xff

def keyGen(key):
    """Generate the two required subkeys"""
    def leftShift(keyBitList):
        """Perform a circular left shift on the first and second five bits"""
        shiftedKey = [None] * KeyLength
        shiftedKey[0:9] = keyBitList[1:10]
        shiftedKey[4] = keyBitList[0]
        shiftedKey[9] = keyBitList[5]
        return shiftedKey

    # Converts input key (integer) into a list of binary digits
    keyList = [(key & 1 << i) >> i for i in reversed(range(KeyLength))]
    permKeyList = [None] * KeyLength
    for index, elem in enumerate(P10table):
        permKeyList[index] = keyList[elem - 1]
    shiftedOnceKey = leftShift(permKeyList)
    shiftedTwiceKey = leftShift(leftShift(shiftedOnceKey))
    subKey1 = subKey2 = 0
    for index, elem in enumerate(P8table):
        subKey1 += (128 >> index) * shiftedOnceKey[elem - 1]
        subKey2 += (128 >> index) * shiftedTwiceKey[elem - 1]
    return (subKey1, subKey2)

def fk(subKey, inputData):
    """Apply Feistel function on data with given subkey"""
    def F(sKey, rightNibble):
        aux = sKey ^ perm(swapNibbles(rightNibble), EPtable)
        index1 = ((aux & 0x80) >> 4) + ((aux & 0x40) >> 5) + \
                 ((aux & 0x20) >> 5) + ((aux & 0x10) >> 2)
        index2 = ((aux & 0x08) >> 0) + ((aux & 0x04) >> 1) + \
                 ((aux & 0x02) >> 1) + ((aux & 0x01) << 2)
        sboxOutputs = swapNibbles((S0table[index1] << 2) + S1table[index2])
        return perm(sboxOutputs, P4table)

    leftNibble, rightNibble = inputData & 0xf0, inputData & 0x0f
    return (leftNibble ^ F(subKey, rightNibble)) | rightNibble

def encrypt(key, plaintext):
    """Encrypt plaintext with given key"""
    data = fk(keyGen(key)[0], ip(plaintext))
    return fp(fk(keyGen(key)[1], swapNibbles(data)))

def decrypt(key, ciphertext):
    """Decrypt ciphertext with given key"""
    data = fk(keyGen(key)[1], ip(ciphertext))
    return fp(fk(keyGen(key)[0], swapNibbles(data)))  

def main_original():
    # Test vectors described in "Simplified DES (SDES)"
    # (http://www2.kinneret.ac.il/mjmay/ise328/328-Assignment1-SDES.pdf)

    try:
        assert encrypt(0b0000000000, 0b10101010) == 0b00010001
    except AssertionError:
        print("Error on encrypt:")
        print("Output: ", encrypt(0b0000000000, 0b10101010), "Expected: ", 0b00010001)
        exit(1)
    try:
        assert encrypt(0b1110001110, 0b10101010) == 0b11001010
    except AssertionError:
        print("Error on encrypt:")
        print("Output: ", encrypt(0b1110001110, 0b10101010), "Expected: ", 0b11001010)
        exit(1)
    try:
        assert encrypt(0b1110001110, 0b01010101) == 0b01110000
    except AssertionError:
        print("Error on encrypt:")
        print("Output: ", encrypt(0b1110001110, 0b01010101), "Expected: ", 0b01110000)
        exit(1)
    try:
        assert encrypt(0b1111111111, 0b10101010) == 0b00000100
    except AssertionError:
        print("Error on encrypt:")
        print("Output: ", encrypt(0b1111111111, 0b10101010), "Expected: ", 0b00000100)
        exit(1)

    t1 = time()
    for _ in range(1000):
        encrypt(0b1110001110, 0b10101010)
    t2 = time()
    print("Elapsed time for 1,000 encryptions: {:0.3f}s".format(t2 - t1))
    exit()

def TripleDES_2key_encrypt(k1: int, k2: int, plaintext: str) -> str:
    ciphertext1 = []
    ciphertext2 = []

    for i in plaintext:
        a = encrypt(k1, ord(i))
        ciphertext1.append(a)

    for i in ciphertext1:
        b = encrypt(k2, i)
        ciphertext2.append(b)
    
    return "".join(chr(i) for i in ciphertext2)

def TripleDES_2key_decrypt(k1: int, k2: int, ciphertext: str) -> str:
    plaintext = ""
    ciphertext1 = []

    for i in ciphertext:
        a = decrypt(k1, ord(i))
        ciphertext1.append(a)

    for i in ciphertext1:
        b = decrypt(k2, i)
        plaintext += chr(b)

    return plaintext

def TripleDES_3key_encrypt(k1: int, k2: int, k3: int, plaintext: str) -> str:
    ciphertext1 = []
    ciphertext2 = []
    ciphertext3 = []

    for i in plaintext:
        a = encrypt(k1, ord(i))
        ciphertext1.append(a)

    for i in ciphertext1:
        b = encrypt(k2, i)
        ciphertext2.append(b)
    
    for i in ciphertext2:
        c = encrypt(k3, i)
        ciphertext3.append(c)

    return "".join(chr(i) for i in ciphertext3)

def TripleDES_3key_decrypt(k1: int, k2: int, k3: int, ciphertext: str) -> str:
    plaintext = ""
    ciphertext1 = []
    ciphertext2 = []

    for i in ciphertext:
        a = decrypt(k1, ord(i))
        ciphertext2.append(a)

    for i in ciphertext2:
        b = decrypt(k2, i)
        ciphertext1.append(b)
    
    for i in ciphertext1:
        c = decrypt(k3, i)
        plaintext += chr(c)

    return plaintext

def cbc_encrypt(k1: int, iv: str, plaintext: str) -> str:
    return "".join(
        chr(encrypt(k1, ord(i) ^ ord(j))) for (i, j) in zip(plaintext, iv)
    )
    
def cbc_decrypt(k1: int, iv: str, ciphertext: str) -> str:
    return "".join(
        chr(decrypt(k1, ord(i)) ^ ord(j)) for (i, j) in zip(ciphertext, iv)
    )

def ctr_encrypt(k1: int, iv: int, plaintext: str) -> str:
    return "".join(
        chr(encrypt(k1, (iv + i) % 256) ^ ord(j)) for i, j in enumerate(plaintext)
    )

def ctr_decrypt(k1: int, iv: int, ciphertext: str) -> str:
    return "".join(
        chr(encrypt(k1, (iv + i) % 256) ^ ord(j)) for i, j in enumerate(ciphertext)
    )

# MAC
def MAC(key: int, msg: str):
    time = 0
    index = 0
    textToProcess = ""

    for i in msg:
        i = ord(i)
        if (time == 0):
            i = encrypt(key, i)
            time = 1
            textToProcess += chr(i)
        else:
            i = i ^ ord(textToProcess[index-1])
            i = encrypt(key, i)
            textToProcess += chr(i)
        index += 1

    print("textProcess: ", textToProcess)
    return textToProcess

# Internal
def encrypt_internal(key: int, message: str):
    F = MAC(key, message)
    F = message + '-----' + F
    textToProcess = ""

    for i in F:
        i = ord(i)
        i = encrypt(key, i)
        textToProcess += chr(i)

    return textToProcess

def decrypt_internal(key: int, ciphertext: str):
    textToProcess = ""
    valid = False
    F = ""

    for i in ciphertext:
        i = ord(i)
        i = decrypt(key, i)
        textToProcess += chr(i)
    
    M = textToProcess.split("-----")[0]
    F = textToProcess.split("-----")[1]

    if MAC(key, M) == F:
      valid = True
    
    return M, valid

# Eksternal
def encrypt_external(key: int, message: str):
    textToProcess = ""

    for i in message:
        i = ord(i)
        i = encrypt(key, i)
        textToProcess += chr(i)

    F = MAC(key, textToProcess)
    F = textToProcess + '-----' + F

    return F

def decrypt_external(key: int, ciphertext: str):
    textToProcess = ""
    valid = False
    F = ""
    
    M = ciphertext.split("-----")[0]
    F = ciphertext.split("-----")[1]

    if MAC(key, M) == F:
       valid = True
       
    for i in M:
        i = ord(i)
        i = decrypt(key, i)
        textToProcess += chr(i)
    
    return textToProcess, valid

if __name__ == '__main__':
    # main_original()
    # st = "WAHYU"
    # key = 0b1110001110
    # for i in st:
    #     a = encrypt(key, ord(i))
    #     b = decrypt(key, a)
    #     print i, " - ", chr(b)
    
    # Contoh Triple Des 2 Key
    print("--- Contoh Triple DES 2 Key ---")
    print("Plain Text: KRESNA")
    enc_2key = TripleDES_2key_encrypt(0b1110001110, 0b1110001110, "KRESNA")
    print("Encrypted: ", enc_2key)

    plain = TripleDES_2key_decrypt(0b1110001110, 0b1110001110, enc_2key)
    print("Decrypted: ", plain, "\n")

    # Contoh Triple Des 3 Key
    print("--- Contoh Triple DES 3 Key ---")
    print("Plain Text: KRESNA")
    enc_3key = TripleDES_3key_encrypt(0b1110001110, 0b1110001110, 0b1110001110, "KRESNA")
    print("Encrypted: ", enc_3key)

    plain = TripleDES_3key_decrypt(0b1110001110, 0b1110001110, 0b1110001110, enc_3key)
    print("Decrypted: ", plain, "\n")

    # Contoh CBC
    print("--- Contoh CBC ---")
    print("Plain Text: KRESNA")
    # IV harus berukuran sama dengan byte plaintext
    iv = "abcdef"
    print("IV: ", iv)
    enc_cbc = cbc_encrypt(0b1110001110, iv, "KRESNA")
    print("Encrypted: ", enc_cbc)

    plain = cbc_decrypt(0b1110001110, iv, enc_cbc)
    print("Decrypted: ", plain, "\n")

    # Contoh CTR
    print("--- Contoh CTR ---")
    print("Plain Text: KRESNA")

    iv = 72
    enc_ctr = ctr_encrypt(0b1110001110, iv, "KRESNA")
    print("Encrypted: ", enc_ctr)

    plain = ctr_decrypt(0b1110001110, iv, enc_ctr)
    print("Decrypted: ", plain, "\n")
  
    key = 0b1110001110
    plaintext = "KRESNA NGGUANTENG 98"

    # MAC
    print("--- MAC ---")
    print("Plain Text: ", plaintext)

    # Contoh Internal
    print("\n--- Contoh Internal ---")
    cipher_internal = encrypt_internal(0b1110001110, plaintext)
    print("Encrypt Internal: ", cipher_internal)

    hasil_internal, valid_internal = decrypt_internal(0b1110001110, cipher_internal)
    print("Dekrip Internal: ", hasil_internal)
    print("Valid Internal: ", valid_internal, "\n")

    # Contoh Eksternal
    print("--- Contoh Eksternal ---")
    cipher_external = encrypt_external(0b1110001110, plaintext)
    print("Encrypt Eksternal: ", cipher_external)

    hasil_external, valid_external = decrypt_external(0b1110001110, cipher_external)
    print("Dekrip Eksternal: ", hasil_external)
    print("Valid Eksternal: ", valid_external, "\n")