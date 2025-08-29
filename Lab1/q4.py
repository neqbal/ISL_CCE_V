import numpy as np

def hill_encrypt(message: str, key: np.ndarray) -> str:
    # Preprocess message
    message = message.upper().replace(" ", "")
    if len(message) % 2 != 0:
        message += "X"  # pad if odd length
    
    # Convert letters to numbers (A=0,...,Z=25)
    numbers = [ord(ch) - ord('A') for ch in message]

    ciphertext = ""
    for i in range(0, len(numbers), 2):
        pair = np.array([[numbers[i]], [numbers[i+1]]])  # column vector (2x1)
        enc_pair = np.dot(key, pair) % 26
        ciphertext += chr(enc_pair[0,0] + ord('A'))
        ciphertext += chr(enc_pair[1,0] + ord('A'))

    return ciphertext


if __name__ == "__main__":
    # Key matrix
    K = np.array([[3, 3],
                  [2, 7]])

    message = "We live in an insecure world"
    ciphertext = hill_encrypt(message, K)

    print("Key Matrix:\n", K)
    print("\nPlaintext:", message)
    print("Ciphertext:", ciphertext)
