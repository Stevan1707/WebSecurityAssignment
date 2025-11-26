import rsa

# The receiver generates original key pair and prepares to send public key to sender
originalPublicKey, originalPrivateKey = rsa.newkeys(1024)
# The interceptor generates fake key pair to tamper the public key
tamperPublicKey, tamperPrivateKey = rsa.newkeys(1024)

originalMessage = "I need 50 dollars to buy some eggs."
oMessageBytes = originalMessage.encode('utf-8')

# The sender encrypts message with tampered public key (thinking it's receiver's)
OEycMessageBytes = rsa.encrypt(oMessageBytes, tamperPublicKey)

# The interceptor intercepts and decrypts the original message
OEycMessage = (rsa.decrypt(OEycMessageBytes, tamperPrivateKey)).decode('utf-8')

# The interceptor tampers message and encrypts with receiver's original public key
tamperMessage = "I need 50000 dollars to buy a car."
tamperMessageBytes = tamperMessage.encode('utf-8')
TEycMessage = rsa.encrypt(tamperMessageBytes, originalPublicKey)

# The receiver decrypts the tampered message
falseMessage = (rsa.decrypt(TEycMessage, originalPrivateKey)).decode('utf-8')

if __name__ == '__main__':
    print("The original message is:", originalMessage)
    print("🔴 The message that interceptor gets is:", OEycMessage)
    print("🔴 The tampered message is:", tamperMessage)
    print("The receiver finally received:", falseMessage)
    if falseMessage == tamperMessage and falseMessage != originalMessage:
        print("🔴 The Man-in-the-middle attack is effective")
    else:
        print("Something went wrong")