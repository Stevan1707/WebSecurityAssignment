import math
import MathUtils
import RSABasic
from RSAAttack import wienerAttack
from rsa.key import PublicKey, PrivateKey


class RSADefence:

    @staticmethod
    def generateDefenceRsaKeys(bitLength=256):
        maxAttempts = 1000
        attempts = 0

        q = MathUtils.generatePrime(bitLength)
        p = MathUtils.generatePrime(bitLength)
        while (p == q or p <= 2 * q) and attempts < maxAttempts:
            p = MathUtils.generatePrime(bitLength)
            attempts += 1

        if attempts >= maxAttempts:
            attempts = 0
            while (p == q or p <= 1.5 * q) and attempts < maxAttempts:
                p = MathUtils.generatePrime(bitLength)
                attempts += 1

        n = p * q
        phi = (p - 1) * (q - 1)

        minD = int(n ** (1 / 3))
        minE = int(math.sqrt(n))

        e = 65537 if 65537 >= minE else MathUtils.generatePrime(16)
        attempts = 0
        while (math.gcd(e, phi) != 1 or e < minE) and attempts < maxAttempts:
            e = MathUtils.generatePrime(16)
            attempts += 1

        d = MathUtils.modinv(e, phi)
        attempts = 0
        while d < minD and attempts < maxAttempts:
            e = MathUtils.generatePrime(16)
            attemptsForE = 0
            while (math.gcd(e, phi) != 1 or e < minE) and attemptsForE < 100:
                e = MathUtils.generatePrime(16)
                attemptsForE += 1

            if math.gcd(e, phi) == 1 and e >= minE:
                d = MathUtils.modinv(e, phi)
            attempts += 1

        if d < minD:
            e = 65537
            while math.gcd(e, phi) != 1:
                e = MathUtils.generatePrime(16)
            d = MathUtils.modinv(e, phi)

        pubKey = PublicKey(n, e)
        privKey = PrivateKey(n, e, d, p, q)
        return pubKey, privKey

    @staticmethod
    def verifyDefenceParams(pubKey, privKey):
        n = pubKey.n
        p = privKey.p
        q = privKey.q
        d = privKey.d
        e = pubKey.e

        verificationResults = {
            "PrimeGapCheck(p>2q)": p > 2 * q,
            "PrivateKeyLowerBound(d≥n^(1/3))": d >= n ** (1 / 3),
            "PublicKeySizeCheck(e≥√n)": e >= math.sqrt(n),
            "PrimeValidity(p)": MathUtils.isPrime(p),
            "PrimeValidity(q)": MathUtils.isPrime(q)
        }
        return verificationResults

    @staticmethod
    def runDefenceTest(bitLength=256):
        print("Generating RSA Keys with Wiener Attack Defence:")
        pubKeyDef, privKeyDef = RSADefence.generateDefenceRsaKeys(bitLength)
        print(f"Public Key Modulus (n): {pubKeyDef.n}")
        print(f"Public Exponent (e): {pubKeyDef.e}")
        print(f"Private Exponent (d): {privKeyDef.d}")
        print(f"Prime p: {privKeyDef.p}")
        print(f"Prime q: {privKeyDef.q}")
        print(f"p/q Ratio: {privKeyDef.p / privKeyDef.q:.2f}\n")

        print("Verifying Defence Parameters:")
        verifyRes = RSADefence.verifyDefenceParams(pubKeyDef, privKeyDef)
        for criterion, result in verifyRes.items():
            status = "PASSED" if result else "FAILED"
            print(f"{criterion}: {status}")
        print("")

        print("Encrypting Test Data:")
        testStr = "WienerDefenceTest"
        testInt = 123456789
        cipherStr = RSABasic.rsaEncrypt(pubKeyDef, testStr, isString=True)
        cipherInt = RSABasic.rsaEncrypt(pubKeyDef, testInt, isString=False)
        print(f"Plaintext String: {testStr} → Ciphertext (hex): {cipherStr.hex()[:40]}...")
        print(f"Plaintext Integer: {testInt} → Ciphertext (hex): {cipherInt.hex()[:40]}...\n")

        print("Attempting Wiener Attack on Defended Keys:")
        crackedKey = wienerAttack(pubKeyDef)
        if crackedKey:
            print("Wiener Attack SUCCEEDED! Defence Mechanism FAILED!")
            try:
                decryptedStr = RSABasic.rsaDecrypt(crackedKey, cipherStr, isString=True)
                decryptedInt = RSABasic.rsaDecrypt(crackedKey, cipherInt, isString=False)
                print(f"Decrypted String: {decryptedStr}")
                print(f"Decrypted Integer: {decryptedInt}")
            except Exception as e:
                print(f"Decryption Failed: {str(e)}")
        else:
            print("Wiener Attack FAILED! Defence Mechanism SUCCEEDED!")


if __name__ == "__main__":
    RSADefence.runDefenceTest(bitLength=128)
