import rsa
import hashlib


def calculateHash(data):
    """计算字节串的SHA256哈希值（修正后仅接收字节串）"""
    return hashlib.sha256(data).digest()

signPublicKey, signPrivateKey = rsa.newkeys(1024)

commuPublicKey, commuPrivateKey = rsa.newkeys(1024)

#generate the signature
commuPub_bytes = commuPublicKey.save_pkcs1()
#calculate the hash of the communiaction public key
commuPub_hash = calculateHash(commuPub_bytes)
sign = rsa.sign(commuPub_bytes, signPrivateKey, 'SHA-256')

#the receiver sends the signature and communication public key to the sender
sent_data = (commuPub_bytes, sign)

#the sender verifies the communication public key.
#the prerequisite is that the source of the signing public key is trustworthy.
received_commuPub_bytes, received_sign = sent_data

if __name__ == "__main__":

    print("======Testing for the absence of man-in-the-middle attacks====== ")
    try:
        rsa.verify(
            received_commuPub_bytes,
            received_sign,
            signPublicKey
        )
        print("The verification passes!")

        #Then the sender try to use the communication key to send the message.
        original_msg = "I need 50 dollars to buy some eggs."
        encrypted_msg = rsa.encrypt(original_msg.encode('utf-8'), commuPublicKey)

        # the receiver gets the message and decrypts
        decrypted_msg = rsa.decrypt(encrypted_msg, commuPrivateKey).decode('utf-8')
        print(f"The message is successfully decrypted: {decrypted_msg}")
    except rsa.VerificationError:
        print("The verification failed! It is suspected of being subjected to a man-in-the-middle attack")

    print("======Testing resistance to man-in-the-middle attacks======")

    attacker_commuPub, attacker_commuPri = rsa.newkeys(1024)
    attacker_commuPub_bytes = attacker_commuPub.save_pkcs1()
    sent_data_attack = (attacker_commuPub_bytes, sign)
    #The sender gets the tampered sign and communication public key
    received_commuPub_attack, received_sign_attack = sent_data_attack

    try:
        # The sender verifies the public key
        rsa.verify(received_commuPub_attack, received_sign_attack, signPublicKey)
        print("The verification passes!")
    except rsa.VerificationError:
        print("The verification failed! It is suspected of being subjected to a man-in-the-middle attack")
        print("Reason: The hash values do not match")