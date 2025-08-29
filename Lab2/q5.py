from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from binascii import unhexlify, hexlify

key_hex = "FEDCBA9876543210FEDCBA9876543210"
key_bytes = unhexlify(key_hex)[:24]

message = b"Top Secret Data"

padded_message = pad(message, AES.block_size)

cipher = AES.new(key_bytes, AES.MODE_ECB)

ciphertext = cipher.encrypt(padded_message)
print("Ciphertext (hex):", hexlify(ciphertext))

decipher = AES.new(key_bytes, AES.MODE_ECB)
decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
print("Decrypted message:", decrypted.decode())
