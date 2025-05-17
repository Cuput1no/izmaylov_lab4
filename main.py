import struct
from const import *


#rotation function
def lshift(val, n):
    n %= w
    return ((val << n) & mask) | ((val & mask) >> (w - n))


def rshift( val, n):
    n %= w
    return ((val & mask) >> n) | (val << (w - n) & mask)


#key initialize functions
def keyAlignment(key):
    if len(key) == 0:
        c = 1
    elif len(key) % w8:
        key += b'\x00' * (w8 - len(key) % w8)

        c = len(key) // w8
    else:
        c = len(key) // w8
    L = [0] * c
    for i in range(len(key) - 1,-1,-1):
        L[i // w8] = (L[i // w8] << 8) + key[i]
    return L,c


def keyExpansion(key):
    P,Q = (0xB7E15163,0x9E3779B9)
    S = [(P+ i * Q) % mod for i in range(T)]
    L,c = keyAlignment(key)

    i = j = A = B = 0
    for _ in range(3*max(c,T)):
        A = S[i] = lshift((S[i] + A + B) % mod, 3)
        B = L[j] = lshift((L[j] + A + B) % mod, (A + B) % w)
        i = (i + 1) % T
        j = (j + 1) % c

    return S

#encryption/decryption fucntions
def encryptionBlock(plaintext,S):
    A,B = struct.unpack('<2I',plaintext)

    A = (A + S[0]) % mod
    B = (B + S[1]) % mod

    for i in range(1,R+1):
        A = (lshift(A ^ B, B % w) + S[2 * i]) % mod
        B = (lshift(B ^ A, A % w) + S[2 * i + 1]) % mod

    return struct.pack('2I',A,B)


def decryptionBlock(ciphertext, S):
    A, B = struct.unpack('<2I', ciphertext)
    for i in range(R, 0, -1):
        B = rshift((B - S[2 * i + 1]) % mod, A % w) ^ A
        A = rshift((A - S[2 * i]) % mod, B % w) ^ B
    B = (B - S[1]) % mod
    A = (A - S[0]) % mod
    return struct.pack('<2I', A, B)


def TASK1(source,sourceSize,key,encryptionMode):
    key_bytes = bytes.fromhex(''.join(f'{x:02X}' for x in key))
    S = keyExpansion(key_bytes)

    result = []
    for i in range(0, sourceSize, 2):
        block = struct.pack('<2I', source[i], source[i + 1])
        if encryptionMode:
            encrypted_block = encryptionBlock(block, S)
            result.extend(struct.unpack('<2I', encrypted_block))
        else:
            decrypted_block = decryptionBlock(block, S)
            result.extend(struct.unpack('<2I', decrypted_block))


    return ' '.join(f'{x:08X}' for x in result)

def main():
    source = [0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210]
    sourceSize = len(source)
    key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10]

    # Encrypt the source
    encrypted_result = TASK1(source, sourceSize, key, encryptionMode=True)
    print("Encrypted:", encrypted_result)

    # Convert encrypted result back to integers for decryption
    encrypted_source = [int(x, 16) for x in encrypted_result.split()]

    # Decrypt the encrypted result
    decrypted_result = TASK1(encrypted_source, sourceSize, key, encryptionMode=False)
    print("Decrypted:", decrypted_result)

    # Check if decrypted result matches the original source
    original_source_str = ' '.join(f'{x:08X}' for x in source)
    if decrypted_result == original_source_str:
        print("Encryption and decryption are correct!")
    else:
        print("Error: Decrypted result does not match the original source.")

# Run the test


if __name__ == "__main__":
    main()