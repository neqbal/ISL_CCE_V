import random

def is_prime(n):
    if n < 2: return False
    for _ in range(5):
        a = random.randrange(2, n-1)
        if pow(a, n-1, n) != 1: return False
    return True

def gen_prime():
    while True:
        p = random.getrandbits(256) | 1
        if is_prime(p): return p

def gcd_ext(a, b):
    if a == 0: return b, 0, 1
    g, x1, y1 = gcd_ext(b % a, a)
    return g, y1 - (b // a) * x1, x1

def mod_inv(e, phi):
    g, x, _ = gcd_ext(e, phi)
    return x % phi

# Generate keys
p, q = gen_prime(), gen_prime()
n = p * q
phi = (p-1) * (q-1)
e = 65537
d = mod_inv(e, phi)

# Message
msg = "Asymmetric Encryption"
m = int.from_bytes(msg.encode(), 'big')

# Encrypt
c = pow(m, e, n)
print(f"Ciphertext: {c}")

# Decrypt
decrypted = pow(c, d, n)
result = decrypted.to_bytes((decrypted.bit_length() + 7) // 8, 'big').decode()

print(f"Original: {msg}")
print(f"Decrypted: {result}")
print(f"Match: {msg == result}")
