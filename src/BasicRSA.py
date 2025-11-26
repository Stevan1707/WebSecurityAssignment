import rsa

publicKey, privateKey = rsa.newkeys(256)

e = publicKey.e
n = privateKey.n
d = privateKey.d
p = privateKey.p
q = privateKey.q

text = "Hello world!"
textBytes = text.encode('utf-8')

EycTextByte = rsa.encrypt(textBytes, publicKey)

DycTextByte = rsa.decrypt(EycTextByte, privateKey)

DycText = DycTextByte.decode('utf-8')

if __name__ == '__main__':
    if text == DycText:
        print("The text is correctly encrypted, also correctly decrypted.")
    else:
        print("The text is not correctly encrypted.")




