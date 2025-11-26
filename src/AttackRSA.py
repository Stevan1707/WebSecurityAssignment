import rsa

from src.BasicRSA import textBytes

#The receiver is trying to send original public key to the sender.
originalPublicKey,originalPrivateKey = rsa.newkeys(1024)
#The key is intercepted and tampered to the interceptor's own public key.
#The public key sent to sender is the interceptor's instead the original one.
tamperPublicKey,tamperPrivateKey = rsa.newkeys(1024)

originalMessage = "I need 50 dollars to buy some eggs."
oMessageBytes = originalMessage.encode('utf-8')

#The sender uses the tamperPublicKey to encrypt his message.
OEycMessageBytes = rsa.encrypt(oMessageBytes,tamperPublicKey)

#The interceptor intercepts the original message and decrypts it.
OEycMessage = (rsa.decrypt(OEycMessageBytes,tamperPrivateKey)).decode('utf-8')

#Then he tampers it and sends it to receiver by using the original public key to encrypt.
tamperMessage = "I need 50000 dollars to buy a car."
tamperMessageBytes = tamperMessage.encode('utf-8')

TEycMessage = rsa.encrypt(tamperMessageBytes,originalPublicKey)
#The receiver gets:
falseMessage = (rsa.decrypt(TEycMessage,originalPrivateKey)).decode('utf-8')

if __name__ == '__main__':
    print("The original message is:",originalMessage)
    print("The message that interceptor gets is:",OEycMessage)
    print("The tamper message is:",tamperMessage)
    print("The receiver finally received:",falseMessage)
    if falseMessage == tamperMessage and falseMessage != originalMessage:
        print("The Man-in-the-middle attack is effective")
    else:
        print("Something went wrong")