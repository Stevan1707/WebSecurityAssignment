import math
import random

import rsa
from rsa.key import PublicKey, PrivateKey
import MathUtils


def generate_rsa_keys(bit_length=256):
    """自主生成密钥参数并封装"""
    p = MathUtils.generate_prime(bit_length)
    q = MathUtils.generate_prime(bit_length)
    while p == q:
        q = MathUtils.generate_prime(bit_length)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    while math.gcd(e, phi) != 1:
        e = MathUtils.generate_prime(16)
    d = MathUtils.modinv(e, phi)

    pub_key = PublicKey(n, e)
    priv_key = PrivateKey(n, e, d, p, q)

    return pub_key, priv_key


def rsa_encrypt(public_key, plaintext, is_string=True):
    """
    添加类型标记位：
    - is_string=True（字符串）：直接加密字节
    - is_string=False（整数）：前缀加\x00标记后加密
    """
    max_len = (public_key.n.bit_length() // 8) - 11

    if is_string:
        # 字符串：直接加密
        plain_bytes = plaintext.encode('utf-8')
        if len(plain_bytes) > max_len:
            raise ValueError(f"字符串过长，最大支持{max_len}字节（当前{len(plain_bytes)}字节）")
        data = plain_bytes
    else:
        # 整数：加\x00标记后加密（避免与字符串混淆）
        byte_len = (plaintext.bit_length() + 7) // 8
        if byte_len + 1 > max_len:  # +1是标记位长度
            raise ValueError(f"整数过大，最大支持{max_len - 1}字节（当前{byte_len}字节）")
        plain_bytes = plaintext.to_bytes(byte_len, byteorder='big')
        data = b'\x00' + plain_bytes  # 标记位：\x00表示整数

    return rsa.encrypt(data, public_key)


def rsa_decrypt(private_key, ciphertext, is_string=True):
    """根据加密时的类型标记解密"""
    try:
        decrypted_bytes = rsa.decrypt(ciphertext, private_key)

        if is_string:
            # 解密字符串：直接解码
            return decrypted_bytes.decode('utf-8')
        else:
            # 解密整数：去掉前缀标记位后转整数
            if decrypted_bytes.startswith(b'\x00'):
                return int.from_bytes(decrypted_bytes[1:], byteorder='big')
            else:
                # 兼容旧数据（无标记位）
                return int.from_bytes(decrypted_bytes, byteorder='big')

    except rsa.DecryptionError:
        raise ValueError("解密失败（密钥不匹配或密文错误）")


# 测试
if __name__ == "__main__":
    pub_key, priv_key = generate_rsa_keys(bit_length=256)
    max_str_len = (pub_key.n.bit_length() // 8) - 11
    max_int_len = max_str_len - 1
    print("=== 密钥信息 ===")
    print(f"字符串最大长度: {max_str_len}字节")
    print(f"整数最大长度: {max_int_len}字节\n")

    # 1. 字符串加解密（指定is_string=True）
    print("=== 字符串加解密 ===")
    plain_str = "Hello world"
    cipher_str = rsa_encrypt(pub_key, plain_str, is_string=True)
    decrypted_str = rsa_decrypt(priv_key, cipher_str, is_string=True)
    print(f"明文: {plain_str}")
    print(f"密文（hex）: {cipher_str.hex()}")
    print(f"解密结果: {decrypted_str}\n")

    # 2. 整数加解密（指定is_string=False）
    print("=== 整数加解密 ===")
    plain_int = random.randint(10000,100000)  # 与"RSA"字节相同的整数
    cipher_int = rsa_encrypt(pub_key, plain_int, is_string=False)
    decrypted_int = rsa_decrypt(priv_key, cipher_int, is_string=False)
    print(f"明文: {plain_int}")
    print(f"密文（hex）: {cipher_int.hex()}")
    print(f"解密结果: {decrypted_int}")