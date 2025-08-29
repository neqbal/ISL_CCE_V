from math import gcd

def additiveENC(plaintext: str, key: int) -> str:
    c = []

    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')

            c.append(chr((ord(ch) - base + key) % 26 + base))
        else:
            c.append(ch)
    return "".join(c)

def additiveDEC(ciphertext: str, key: int) -> str:
    p = []

    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')

            p.append(chr((ord(ch) - base - key) % 26 + base))
        else:
            p.append(ch)
    return "".join(p)


def multENC(plaintext: str, key: int) -> str:
    if gcd(key, 26) != 1:
        raise ValueError("Key must be coprime of 26")

    c = []
    
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')

            c.append(chr(((ord(ch) - base) * key) % 26 + base))
        else:
            c.append(ch)
    return "".join(c)


def modInverse(a: int, m: int) -> int:
    for i in range(1, m):
        if (a*i)%m == 1:
            return i
    raise ValueError("No modular inverse")


def multDEC(ciphertext: str, key: int) -> str:
    p = []
    
    key_inv = modInverse(key, 26)

    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')

            p.append(chr(((ord(ch) - base)*key_inv) % 26 + base))
        else:
            p.append(ch)

    return "".join(p)

def affineENC(plaintext: str, key: list[int]) -> str:
    if gcd(key[0], 26) != 1:
        raise ValueError("K1 must be co prime of 26")

    c = []
    
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')

            c.append(chr(((ord(ch) - base)*key[0] + key[1]) % 26 + base))
        else:
            c.append(ch)

    return "".join(c)


def affineDEC(ciphertext: str, key: list[int]) -> str:
    p = []
    key_inv = modInverse(key[0], 26)

    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')

            p.append(chr((((ord(ch) - base) - key[1])*key_inv) % 26 + base))
        else:
            p.append(ch)

    return "".join(p)


p = "I am learning information security"

while True:
    choice = int(input("1: Additive\n2: Multiplicative\n3: Affine\n"))
    if choice == 1:
        cipher = additiveENC(p, 20)
        print(cipher)
        print(additiveDEC(cipher, 20))
    elif choice == 2:
        cipher = multENC(p, 15)
        print(cipher)
        print(multDEC(cipher, 15))
    elif choice == 3:
        cipher = affineENC(p, [15, 20])
        print(cipher)
        print(affineDEC(cipher, [15, 20]))
    else:
        break
