import math
import random


def isPrime(n, k=5):

    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0:
        return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generatePrime(bitLength):

    while True:
        num = random.getrandbits(bitLength)
        num |= (1 << (bitLength - 1)) | 1
        if isPrime(num):
            return num


def extendedGcd(a, b):

    if a == 0:
        return b, 0, 1
    else:
        g, y, x = extendedGcd(b % a, a)
        return g, x - (b // a) * y, y


def modinv(a, m):
    g, x, y = extendedGcd(a, m)
    if g != 1:
        raise ValueError('Modular inverse does not exist')
    else:
        return x % m

def continuedFraction(a, b):
    coeffs = []
    while b != 0:
        q = a // b
        coeffs.append(q)
        a, b = b, a % b
    return coeffs


def convergents(coeffs):
    convs = []
    hPrevPrev, hPrev = 0, 1
    kPrevPrev, kPrev = 1, 0
    for c in coeffs:
        h = c * hPrev + hPrevPrev
        k = c * kPrev + kPrevPrev
        convs.append((h, k))
        hPrevPrev, hPrev = hPrev, h
        kPrevPrev, kPrev = kPrev, k
    return convs


def isPerfectSquare(n):
    if n < 0:
        return False
    sqrtN = math.isqrt(n)
    return sqrtN * sqrtN == n
