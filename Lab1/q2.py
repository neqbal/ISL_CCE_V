def getbase(ch: str) -> int:
    return ord("A") if ch.isupper() else ord("a")


def vignereENC(plaintext: str, key: str) -> str:
    c = []
    idx = 0
    key.upper()

    for ch in plaintext:
        if ch.isalpha():
            base = getbase(ch)
            
            shift = ord(key[idx % len(key)]) - ord('A')
            c.append(chr((ord(ch) - base + shift) % 26 + base))
            idx += 1
        else:
            c.append(ch)

    return "".join(c)


def vignereDEC(ciphertext: str, key: str) -> str:
    p = []
    idx = 0
    key.upper()

    for ch in ciphertext:
        if ch.isalpha():
            base = getbase(ch)

            shift = ord(key[idx % len(key)]) - ord('A')
            p.append(chr((ord(ch[0]) - base - shift) % 26 + base))
            idx += 1
        else:
            p.append(ch)

    return "".join(p)


def autokeyENC(plaintext: str, key: str) -> str:
    ciphertext = []
    key = key.upper()
    extended_key = key
    key_index = 0

    for ch in plaintext:
        if ch.isalpha():
            base = getbase(ch)
            shift = ord(extended_key[key_index]) - ord('A')
            c = (ord(ch.upper()) - ord('A') + shift) % 26
            ciphertext.append(chr(c + base))
            extended_key += ch.upper()
            key_index += 1
        else:
            ciphertext.append(ch)

    return "".join(ciphertext)


def autokeyDEC(ciphertext: str, key: str) -> str:
    plaintext = []
    key = key.upper()
    extended_key = key
    key_index = 0

    for ch in ciphertext:
        if ch.isalpha():
            base = getbase(ch)
            shift = ord(extended_key[key_index]) - ord('A')
            p = (ord(ch.upper()) - ord('A') - shift) % 26
            plaintext.append(chr(p + base))
            extended_key += chr(p + ord('A'))
            key_index += 1
        else:
            plaintext.append(ch)

    return "".join(plaintext)


p = "the house is being sold tonight"
cipher = vignereENC(p, "dollars")
print(f"Vignere Encrypt: {cipher}")
print(f"Vignere decrypt: {vignereDEC(cipher, "dollars")}")


cipher = autokeyENC(p, chr(7 + 65))
print(f"Autokey Encrypt: {cipher}")
print(f"Autokey decrypt: {autokeyDEC(cipher, chr(7 + 65))}")
