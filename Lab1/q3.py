def genMatrix(key: str):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    key = key.upper().replace("J", "I")
    matrix = []
    used = set()

    for ch in key:
        if ch not in used and ch in alphabet:
            matrix.append(ch)
            used.add(ch)

    for ch in alphabet:
        if ch == "J":
            ch = "I"
        if ch not in used:
            matrix.append(ch)
            used.add(ch)

    return [matrix[i*5:(i+1)*5] for i in range(5)]


def genPair(pt: str):
    pt = pt.upper().replace("J", "I")
    pt = "".join(ch for ch in pt if ch.isalpha())

    pairs = []
    i = 0

    while i < len(pt):
        a = pt[i]
        b = pt[i+1] if i + 1 < len(pt) else "X"

        if a == b:
            pairs.append(a + "X")
            i += 1
        else:
            pairs.append(a + b)
            i += 2
    return pairs


def findPos(matrix, ch):
    for row in range(5):
        for col in range(5):
            if ch == matrix[row][col]:
                return row, col
    
    return 0, 0

def encPair(matrix, pair):
    a, b = pair

    row1, col1 = findPos(matrix, a)
    row2, col2 = findPos(matrix, b)

    if row1 == row2:
        return matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
    elif col1 == col2:
        return matrix[(row1+1) % 5][col1] + matrix[(row2+1) % 5][col2]
    else:
        return matrix[row1][col2] + matrix[row2][col1]


def playfairENC(message: str, keyword: str):
    matrix = genMatrix(keyword)
    pairs = genPair(message)
    ciphertext = "".join(encPair(matrix, pair) for pair in pairs)
    return ciphertext, matrix, pairs


message = "The key is hidden under the door pad"
keyword = "GUIDANCE"

ciphertext, matrix, pairs = playfairENC(message, keyword)

print("Playfair Matrix:")
for row in matrix:
    print(row)

print("\nPlaintext pairs:", pairs)
print("Ciphertext:", ciphertext)
