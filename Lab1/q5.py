def findKey(ct: str, pt: str):
    ct = ct.upper()
    pt = pt.upper()
    keys = []
    for a, b in zip(ct, pt):
        a = ord(a) - 65
        b = ord(b) - 65
        keys.append((a - b) % 26)

    if all(k == keys[0] for k in keys):
        return keys[0]
    else:
        return keys

print(findKey("CIW", "yes"))
