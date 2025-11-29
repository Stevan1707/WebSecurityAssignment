from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from self_implementation import DH
from DHattack import MITMattacker


class AuthDefense:
    def __init__(self, p=23, g=5):
        self.dh = DH(p, g)
        self.sign_key = RSA.generate(2048)
        self.public_key = self.sign_key.publickey()
    
    def get_signed_public_key(self):
        self.dh.generate_keys()  # Generate DH key pair
        h = SHA256.new(str(self.dh.public_key).encode())  # sign the public key
        signature = pkcs1_15.new(self.sign_key).sign(h)
        
        return {
            'public_key': str(self.dh.public_key),
            'signature': signature,
            'verification_key': self.public_key.export_key()
        }
    
    def verify_and_set_shared_key(self, signed_data):
        other_key = RSA.import_key(signed_data['verification_key'])  # Import other party's verification public key
        
        try:
            h = SHA256.new(signed_data['public_key'].encode())  # verify the signature
            pkcs1_15.new(other_key).verify(h, signed_data['signature'])
            
            other_public = int(signed_data['public_key'])  #  shared key established after signature veryfied
            return self.dh.get_shared_key(other_public)
        except:
            return None


def main():
    p = 23
    g = 5
    
    print(f"public parameters: p={p}, g={g}")
    print()
    
    print("-- Communication demo with signature --")
    alice = AuthDefense(p, g)
    bob = AuthDefense(p, g)
    
    alice_key = alice.get_signed_public_key()  # generate a signed public key
    bob_key = bob.get_signed_public_key()
    
    print(f"Alice's public key: {alice_key['public_key']}")
    print(f"Bob's public key: {bob_key['public_key']}")
    print()
    
    alice_shared = alice.verify_and_set_shared_key(bob_key)  # verify public key and establish a shared key
    bob_shared = bob.verify_and_set_shared_key(alice_key)
    
    if alice_shared and bob_shared:
        print("Signature verification successful")
        print(f"Alice's shared key: {alice_shared}")
        print(f"Bob's shared key: {bob_shared}")
        
        if alice_shared == bob_shared:
            print("Shared key matching")
            print("The safe passage has been successfully established")

            print()
            
            print("--- Demo of secure message transmission ---")
            message = "Hello Bob!"
            print(f"[Alice] original message: {message}")
            
            key_str = str(alice_shared)  # Aliceencrypt the message
            message_bytes = message.encode()
            encrypted = bytes([b ^ ord(key_str[i % len(key_str)]) for i, b in enumerate(message_bytes)])
            print(f"[Alice] encrypt and send: {encrypted.hex()}")
            
            bob_key_str = str(bob_shared)  # Bob decrypt the message
            decrypted = bytes([b ^ ord(bob_key_str[i % len(bob_key_str)]) for i, b in enumerate(encrypted)])
            print(f"[Bob] decrypt and receive the message: '{decrypted.decode()}'")
            print("Message transmission is secure. It soesn't be altered")
            
        else:
            print("Shared key does not match")
    else:        
        print("Signature verification failed")
        print("Possibly exist man-in-the-middle attack")
    
    print()

    print("-- Defence demo --")
    print("Attacker try to intercept and alter the message...")
    
    alice_secure = AuthDefense(p, g)
    bob_secure = AuthDefense(p, g)
    
    alice_signed_key = alice_secure.get_signed_public_key()  # Alice and Bob generate signed public key
    bob_signed_key = bob_secure.get_signed_public_key()
    
    print(f"Alice's original public key': {alice_signed_key['public_key']}")
    print(f"Bob's original public key': {bob_signed_key['public_key']}")

    print()
    
    print("[Attacker] attempt to alter Alice's public key...")
    attacker_fake_alice_key = {
        'public_key': '999',  # fake public key
        'signature': alice_signed_key['signature'], 
        'verification_key': alice_signed_key['verification_key']
    }
    
    print("[Bob] try to verify received public key...")  # try to verify altered key
    bob_shared_with_fake = bob_secure.verify_and_set_shared_key(attacker_fake_alice_key)
    
    if bob_shared_with_fake is None:
        print("Public key alteration detected, connection rejected")
    else:
        print("Verification failed, alteration undetected")
    
    print()
    
    print("Normal public key exchange(without alteration)...")
    alice_shared_normal = alice_secure.verify_and_set_shared_key(bob_signed_key)
    bob_shared_normal = bob_secure.verify_and_set_shared_key(alice_signed_key)
    
    if alice_shared_normal and bob_shared_normal:
        print("Signature verification success, safe channel established")
        print(f"Alice's shared key': {alice_shared_normal}")
        print(f"Bob's shared key: {bob_shared_normal}")
        
        if alice_shared_normal == bob_shared_normal:
            print("Shared key matching, communication safe")
        else:
            print("Shared key does not match")
    else:
        print("Normal exchange failed")
    


if __name__ == "__main__":
    main()