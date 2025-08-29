def modInv(a, m):
    for i in range(1, m):
        if (a*i) % m == 1:
            return i
    return 0

def findKey(pt: str, ct: str):
    pt = pt.upper()
    ct = ct.upper()

    P1, P2 = ord(pt[0]) - 65, ord(pt[1]) - 65
    C1, C2 = ord(ct[0]) - 65, ord(ct[1]) - 65

    diffP = (P2 - P1)%26
    diffC = (C2 - C1)%26
    inv_diffP = modInv(diffP, 26)

    a = (diffC*inv_diffP) % 26

    b = (C1 - a*P1)%26

    return a, b

def affineDEC(ct: str, a: int, b: int):
    p = []
    a_inv = modInv(a, 26)
    for ch in ct:
        p.append(chr(((ord(ch) - 65 - b)*a_inv)%26 + 65))

    return "".join(p)

a, b = findKey("ab", "GL")
print(a, b)
print(affineDEC("XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS", a, b ))
