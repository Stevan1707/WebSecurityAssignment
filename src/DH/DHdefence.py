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
    alice = AuthDefense()
    bob = AuthDefense()
    
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
        else:
            print("Shared key does not match")
    else:        
        print("Signature verification failed")
        print("Possibly exist man-in-the-middle attack")



if __name__ == "__main__":
    main()
        