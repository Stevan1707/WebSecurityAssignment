import math
import random
import sympy as sp

def generatePrime(bitLength):
    while True:
        num = random.getrandbits(bitLength)
        if num > 1 and sp.isprime(num):
            return num

def generatePQ(bitLength):
    while True:
        p = generatePrime(bitLength)
        q = generatePrime(bitLength)
        if q < p < 2 * q:
            return p, q

def sqrt(n):
    if n < 0:
        return -1
    x = int(math.isqrt(n))
    return x if x*x == n else -1