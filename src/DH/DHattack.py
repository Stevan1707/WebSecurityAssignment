from self_implementation import DH


class MITMattacker:
    def __init__(self, p, g):
        self.p = p
        self.g = g
        self.attacker = DH(p, g)  # instance of the attacker
        self.A_shared_key = None    # shared key a
        self.B_shared_key = None      # shared key b

    def get_and_replace_public_key(self, public_key):
        altered_public = self.attacker.generate_keys()
        print(f"[attacker] Get original public key: {public_key}")
        print(f"[attacker] Replaced the public key with: {altered_public}")
        return altered_public
    
    def establish_shared_key_A(self, A_public_key):  # Establish a shared key with A
        self.A_shared_key = self.attacker.get_shared_key(A_public_key)
        print(f"[attacker] Established a shared key with A: {self.A_shared_key}")
        return self.A_shared_key
    
    def establish_shared_key_B(self, B_public_key):  # Establish a shared key with B
        self.B_shared_key = self.attacker.get_shared_key(B_public_key)
        print(f"[attacker] Established a shared key with B: {self.B_shared_key}")
        return self.B_shared_key

    def decrypt_and_encrypt_message(self, encrypted_message, from_A = True):
        key = self.A_shared_key if from_A else self.B_shared_key  # choose correct key 
        key_str = str(key)

        decrypted = bytes([b ^ ord(key_str[i % len(key_str)]) for i, b in enumerate(encrypted_message)]) # decrypt message
        original_message = decrypted.decode()
        print(f"[attacker] Get and decrypted message: {original_message}")

        if "Hello" in original_message:
            modified_message = original_message.replace("Hello", "HACKED")
            print(f"[attacker] Modified the message: {modified_message}")
        else:
            modified_message = original_message
        
        target_key = self.B_shared_key if from_A else self.A_shared_key  # re-encrypt and send to receiver
        target_key_str = str(target_key)
        re_encrypted = bytes([b ^ ord(target_key_str[i % len(target_key_str)]) 
                             for i, b in enumerate(modified_message.encode())])
        
        return re_encrypted
    

def main():
    p = 23
    g = 5

    print(f"public parameters: p={p}, g={g}")
    print()

    alice = DH(p, g)
    bob = DH(p, g)
    attacker = MITMattacker(p, g)

    print("General key generating......")
    alice_public = alice.generate_keys()
    bob_public = bob.generate_keys() 
    print(f"Alice: Private key={alice.private_key}, Public key={alice_public}")
    print(f"Bob:   Private key={bob.private_key}, Public key={bob_public}")
    print()

    print("Attack start......")
    fake_alice_public = attacker.get_and_replace_public_key(alice_public)
    bob_shared_with_attacker = bob.get_shared_key(fake_alice_public)  # the time when Bob received altered key
    print(f"[Bob] use fake public key to calculate shared key: {bob_shared_with_attacker}")
    attacker.establish_shared_key_B(bob_public)  # attacker establishes a shared key with Bob

    fake_bob_public = attacker.get_and_replace_public_key(bob_public)
    alice_shared_with_attacker = alice.get_shared_key(fake_bob_public)   # the time when Bob received altered key
    print(f"[Alice] use fake public key to calculate shared key: {alice_shared_with_attacker}")
    attacker.establish_shared_key_A(alice_public)  # attacker establishes a shared key with Alice

    print()

    print('--Result verification--')
    print(f"Alice's shared key:{alice_shared_with_attacker}")
    print(f"Bob's shared key:{bob_shared_with_attacker}")
    print(f"Attacker's key with Alice:{attacker.A_shared_key}")
    print(f"Attacker's key with Bob:{attacker.B_shared_key}")

    if (alice_shared_with_attacker == attacker.A_shared_key and bob_shared_with_attacker == attacker.B_shared_key):
        print("Attack success")
    else:
        print("Attack falied")
    print()

    print("--Message Passing Demonstration (Alice send to Bob)--")
    message = "Hello Bob!"
    print(f"[Alice] original message:{message}")

    key_str = str(alice_shared_with_attacker)  # Alice encrypts the message (using a shared key with the attacker)
    message_bytes = message.encode()
    encrypted = bytes([b ^ ord(key_str[i % len(key_str)]) for i,b in enumerate(message_bytes)])
    print(f"[Alice] encrypt and send:{encrypted.hex()}")

    re_encrypted = attacker.decrypt_and_encrypt_message(encrypted, from_A=True)  # attacker intercepts, decrypts, modifies and re-encrypts the message
    print(f"[Attacker] to Bob:{re_encrypted.hex()}")

    bob_key_str = str(bob_shared_with_attacker)  # Bob receive and decrypt message
    decrypted_by_bob = bytes([b ^ ord(bob_key_str[i % len(bob_key_str)]) for i,b in enumerate(re_encrypted)])
    print(f"[Bob] decrypt and receive message:'{decrypted_by_bob.decode()}")

    if "HACKED" in decrypted_by_bob.decode():
        print("-message alteration success")
    print()

    print("--Message Passing Demonstration (Bob send to Alice)--")



if __name__ == "__main__":
    main()