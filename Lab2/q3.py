from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
import time

message = b"Performance Testing of Encryption Algorithms"

des_key = b"8bytekey"
aes_key = b"thisis32byteslongpassphraseimok!"

des_cipher = DES.new(des_key, DES.MODE_ECB)

start = time.time()
des_ciphertext = des_cipher.encrypt(pad(message, DES.block_size))
des_enc_time = time.time() - start

start = time.time()
des_decrypted = unpad(des_cipher.decrypt(des_ciphertext), DES.block_size)
des_dec_time = time.time() - start

aes_cipher = AES.new(aes_key, AES.MODE_ECB)

start = time.time()
aes_ciphertext = aes_cipher.encrypt(pad(message, AES.block_size))
aes_enc_time = time.time() - start

start = time.time()
aes_decrypted = unpad(aes_cipher.decrypt(aes_ciphertext), AES.block_size)
aes_dec_time = time.time() - start

print("DES   - Encryption Time: {:.6f} sec".format(des_enc_time))
print("DES   - Decryption Time: {:.6f} sec".format(des_dec_time))
print("AES-256 - Encryption Time: {:.6f} sec".format(aes_enc_time))
print("AES-256 - Decryption Time: {:.6f} sec".format(aes_dec_time))
