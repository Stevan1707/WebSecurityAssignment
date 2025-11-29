import math
import random
import RSABasic
from rsa.key import PrivateKey
import MathUtils

def generateVulnerableRsaKeys(bitLength=128):
    q = MathUtils.generatePrime(bitLength)
    p = MathUtils.generatePrime(bitLength)
    while p == q or not (q < p < 1.5 * q):
        p = MathUtils.generatePrime(bitLength)

    n = p * q
    phi = (p - 1) * (q - 1)

    # Generate smaller d (primes under 40, ensuring d < n^(1/4)/3)
    d = random.choice([3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37])
    while math.gcd(d, phi) != 1:
        d = random.choice([3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37])
    e = MathUtils.modinv(d, phi)

    # Encapsulate as rsa library Key object
    pubKey = RSABasic.PublicKey(n, e)
    privKey = RSABasic.PrivateKey(n, e, d, p, q)
    return pubKey, privKey

def wienerAttack(publicKey):
    e = publicKey.e
    n = publicKey.n

    coeffs = MathUtils.continuedFraction(e, n)
    if not coeffs:
        return None

    convs = MathUtils.convergents(coeffs)



    for h, k in convs + convs[::-1]:
        if h == 0 or k == 0 or k > n ** (1 / 4):
            continue

        if (e * k - 1) % h != 0:
            continue
        phiCandidate = (e * k - 1) // h

        if (e * k) % phiCandidate != 1:
            continue

        pPlusQ = n - phiCandidate + 1
        discriminant = pPlusQ ** 2 - 4 * n
        if not MathUtils.isPerfectSquare(discriminant):
            continue
        sqrtD = math.isqrt(discriminant)

        p = (pPlusQ + sqrtD) // 2
        q = (pPlusQ - sqrtD) // 2

        #Final verification: p*q == n and both are prime
        if p * q == n and MathUtils.isPrime(p) and MathUtils.isPrime(q):
            return PrivateKey(n, e, k, p, q)

    return None

if __name__ == "__main__":
    #We first generate the vulnerable RSA keys
    print("=== Generating RSA keys vulnerable to Wiener attack:")
    pubKeyVuln, privKeyVuln = generateVulnerableRsaKeys(bitLength=128)
    n14 = pubKeyVuln.n ** (1 / 4)
    print(f"Public key (n): {pubKeyVuln.n}")
    print(f"Public key (e): {pubKeyVuln.e}")
    print(f"Real private key (d): {privKeyVuln.d}")
    print(f"Wiener condition check: d={privKeyVuln.d} < n^(1/4)/3 ≈ {n14 / 3:.2f} → {privKeyVuln.d < n14 / 3}\n")

    # Then encrypt the data
    print("Encrypting test data :")
    testStr = "WienerSuccess"
    testInt = random.randint(10000, 100000)
    cipherStr = RSABasic.rsaEncrypt(pubKeyVuln, testStr, isString=True)
    cipherInt = RSABasic.rsaEncrypt(pubKeyVuln, testInt, isString=False)


    #Executing Wiener attack
    print("Executing Wiener attack: ")
    crackedPrivKey = wienerAttack(pubKeyVuln)
    if crackedPrivKey:
        print("###Attack successful!")
        print(f"Cracked private key (d): {crackedPrivKey.d}")
        print(f"Cracked prime (p): {crackedPrivKey.p}")
        print(f"Cracked prime (q): {crackedPrivKey.q}\n")

        print("Verifying decryption results: ")
        decryptedStr = RSABasic.rsaDecrypt(crackedPrivKey, cipherStr, isString=True)
        decryptedInt = RSABasic.rsaDecrypt(crackedPrivKey, cipherInt, isString=False)
        print(f"Decrypted string: {decryptedStr}")
        print(f"Decrypted integer: {decryptedInt}")
    else:
        print("###Attack failed! (Please rerun or adjust d value)")
