import math
import random


def is_prime(n, k=5):
    """Miller-Rabin素性检测（自主实现大素数检测）"""
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


def generate_prime(bit_length):
    """自主生成指定比特长度的大素数"""
    while True:
        num = random.getrandbits(bit_length)
        num |= (1 << (bit_length - 1)) | 1  # 确保比特长度和奇数
        if is_prime(num):
            return num


def extended_gcd(a, b):
    """自主实现扩展欧几里得算法"""
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = extended_gcd(b % a, a)
        return g, x - (b // a) * y, y


def modinv(a, m):
    """自主计算模逆"""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError('模逆不存在')
    else:
        return x % m