import random


class DH:
    def __init__(self, p, g):
        self.p = p  # public disclosed large prime number
        self.g = g  # public generator
        self.private_key = None  # private key
        self.public_key = None   # public
    
    def generate_keys(self):
        self.private_key = random.randint(2, self.p - 2)  # generate private key
        self.public_key = pow(self.g, self.private_key, self.p)  # g^pri \mod p
        return self.public_key
    
    def get_shared_key(self, other_public_key):
        if self.private_key is None:
            raise ValueError("key pair generation required")
        
        shared_key = pow(other_public_key, self.private_key, self.p)
        return shared_key


def main():
    # Choose public parameters
    p = 23  # prime number
    g = 5   # generator
  
    print(f"public parameters: p={p}, g={g}")
    print()
    
    # Create a D-H instance
    alice = DH(p, g)
    bob = DH(p, g)
    
    # Generate a key pair
    alice_public = alice.generate_keys()
    bob_public = bob.generate_keys()
    
    print(f"Alice: Private key={alice.private_key}, Public key={alice_public}")
    print(f"Bob:   Private key={bob.private_key}, Public key={bob_public}")
    
    print()
    
    print("Exchanging the public key and calculating the shared key...")
    alice_shared = alice.get_shared_key(bob_public)
    bob_shared = bob.get_shared_key(alice_public)
    
    # Verify result
    if alice_shared == bob_shared:
        # encrypt process
        message = "Hello Bob!"
        shared_key = alice.get_shared_key(bob_public)
        print(f"Original message: {message}")
        print(f"Key: {shared_key}")
        
        # XOR encrypt
        message_bytes = message.encode()
        key_str = str(shared_key)
        encrypted = bytes([b ^ ord(key_str[i % len(key_str)]) for i, b in enumerate(message_bytes)])
        print(f"Encrypt result: {encrypted.hex()}")
        
        # Decrypt
        decrypted = bytes([b ^ ord(key_str[i % len(key_str)]) for i, b in enumerate(encrypted)])
        print(f"Decrypt result: {decrypted.decode()}")
        
    # For exchange failed case
    else:
        print("Exchange failed")
    

if __name__ == "__main__":
    main()