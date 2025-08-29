from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

message = b"Classified Text"

K1 = b"\x12\x34\x56\x78\x90\xAB\xCD\xEF" 
K2 = b"\x12\x34\x56\x78\x90\xAB\xCD\xEF"
K3 = b"\x12\x34\x56\x78\x90\xAB\xCD\xEF"

padded_msg = pad(message, DES.block_size)

des1 = DES.new(K1, DES.MODE_ECB)
c1 = des1.encrypt(padded_msg)

des2 = DES.new(K2, DES.MODE_ECB)
c2 = des2.decrypt(c1)

des3 = DES.new(K3, DES.MODE_ECB)
ciphertext = des3.encrypt(c2)

print("Ciphertext (hex):", ciphertext.hex())

c3 = des3.decrypt(ciphertext)

c4 = des2.encrypt(c3)

decrypted = unpad(des1.decrypt(c4), DES.block_size)

print("Decrypted text:", decrypted.decode())
