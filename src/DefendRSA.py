import rsa
import hashlib


def calculateHash(data):
    """Calculate SHA256 hash value of byte string (modified to accept only byte strings)"""
    return hashlib.sha256(data).digest()

# Generate signature key pair (private key for signing, public key for verification)
signPublicKey, signPrivateKey = rsa.newkeys(1024)

# Generate communication key pair (public key for encryption, private key for decryption)
commuPublicKey, commuPrivateKey = rsa.newkeys(1024)

# Generate signature for communication public key
commuPub_bytes = commuPublicKey.save_pkcs1()
# Calculate hash of communication public key
commuPub_hash = calculateHash(commuPub_bytes)
sign = rsa.sign(commuPub_bytes, signPrivateKey, 'SHA-256')

# Receiver sends signature and communication public key to sender
sent_data = (commuPub_bytes, sign)
received_commuPub_bytes, received_sign = sent_data

if __name__ == "__main__":
    print("======Testing: No man-in-the-middle attack (normal communication)====== ")
    try:
        # Sender verifies the legitimacy of communication public key
        rsa.verify(
            received_commuPub_bytes,
            received_sign,
            signPublicKey
        )
        print("✅ The verification passes!")

        # Sender encrypts message with verified communication public key
        original_msg = "I need 50 dollars to buy some eggs."
        encrypted_msg = rsa.encrypt(original_msg.encode('utf-8'), commuPublicKey)

        # Receiver decrypts the message
        decrypted_msg = rsa.decrypt(encrypted_msg, commuPrivateKey).decode('utf-8')
        print(f"The message is successfully decrypted: {decrypted_msg}")
    except rsa.VerificationError:
        print("❌ The verification failed! It is suspected of being subjected to a man-in-the-middle attack")

    print("\n======Testing: Resisting man-in-the-middle attack (attack scenario)======")
    # 🔴 Attacker generates fake communication key pair
    attacker_commuPub, attacker_commuPri = rsa.newkeys(1024)
    attacker_commuPub_bytes = attacker_commuPub.save_pkcs1()
    # 🔴 Attacker replaces communication public key with fake one, reuses original signature
    sent_data_attack = (attacker_commuPub_bytes, sign)
    # Sender receives tampered public key and original signature
    received_commuPub_attack, received_sign_attack = sent_data_attack

    try:
        # Sender verifies the tampered public key
        rsa.verify(received_commuPub_attack, received_sign_attack, signPublicKey)
        print("✅ The verification passes!")
    except rsa.VerificationError:
        print("❌ The verification failed! It is suspected of being subjected to a man-in-the-middle attack")
        print("🔴 Reason: Hash value of fake public key does not match the signature hash")