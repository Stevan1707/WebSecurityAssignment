import math
import random

import rsa
from rsa.key import PublicKey, PrivateKey
import MathUtils


def generateRsaKeys(bitLength=256):
    p = MathUtils.generatePrime(bitLength)
    q = MathUtils.generatePrime(bitLength)
    while p == q:
        q = MathUtils.generatePrime(bitLength)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    while math.gcd(e, phi) != 1:
        e = MathUtils.generatePrime(16)
    d = MathUtils.modinv(e, phi)

    pubKey = PublicKey(n, e)
    privKey = PrivateKey(n, e, d, p, q)

    return pubKey, privKey


def rsaEncrypt(publicKey, plaintext, isString=True):

    maxLen = (publicKey.n.bit_length() // 8) - 11

    if isString:
        # String: encrypt directly
        plainBytes = plaintext.encode('utf-8')
        if len(plainBytes) > maxLen:
            raise ValueError(f"String too long, maximum supported {maxLen} bytes (current {len(plainBytes)} bytes)")
        data = plainBytes
    else:
        # Integer: add \x00 marker then encrypt (avoid confusion with strings)
        byteLen = (plaintext.bit_length() + 7) // 8
        if byteLen + 1 > maxLen:  # +1 is the length of the marker
            raise ValueError(f"Integer too large, maximum supported {maxLen - 1} bytes (current {byteLen} bytes)")
        plainBytes = plaintext.to_bytes(byteLen, byteorder='big')
        data = b'\x00' + plainBytes  # Marker: \x00 indicates integer

    return rsa.encrypt(data, publicKey)


def rsaDecrypt(privateKey, ciphertext, isString=True):
    try:
        decryptedBytes = rsa.decrypt(ciphertext, privateKey)

        if isString:
            # Decrypt string: decode directly
            return decryptedBytes.decode('utf-8')
        else:
            # Decrypt integer: remove prefix marker and convert to integer
            if decryptedBytes.startswith(b'\x00'):
                return int.from_bytes(decryptedBytes[1:], byteorder='big')
            else:
                # Compatible with old data (no marker)
                return int.from_bytes(decryptedBytes, byteorder='big')

    except rsa.DecryptionError:
        raise ValueError("Decryption failed (key mismatch or incorrect ciphertext)")


# Testing
if __name__ == "__main__":
    pubKey, privKey = generateRsaKeys(bitLength=256)
    maxStrLen = (pubKey.n.bit_length() // 8) - 11
    maxIntLen = maxStrLen - 1
    print("Key Information:")
    print(f"Maximum string length: {maxStrLen} bytes")
    print(f"Maximum integer length: {maxIntLen} bytes\n")

    # 1. String encryption/decryption (specify isString=True)
    print("String Encryption/Decryption:")
    plainStr = "Hello world"
    cipherStr = rsaEncrypt(pubKey, plainStr, isString=True)
    decryptedStr = rsaDecrypt(privKey, cipherStr, isString=True)
    print(f"Plaintext: {plainStr}")
    print(f"Ciphertext (hex): {cipherStr.hex()}")
    print(f"Decryption result: {decryptedStr}\n")

    # 2. Integer encryption/decryption (specify isString=False)
    print("Integer Encryption/Decryption :")
    plainInt = random.randint(10000,100000)
    cipherInt = rsaEncrypt(pubKey, plainInt, isString=False)
    decryptedInt = rsaDecrypt(privKey, cipherInt, isString=False)
    print(f"Plaintext: {plainInt}")
    print(f"Ciphertext (hex): {cipherInt.hex()}")
    print(f"Decryption result: {decryptedInt}")
