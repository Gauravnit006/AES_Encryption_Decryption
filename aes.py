from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Generate a random key
key = get_random_bytes(16)  # 128-bit key for AES

# Encryption
cipher = AES.new(key, AES.MODE_CBC)
plaintext = b'This is a secret message'
ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
print('Ciphertext message: ', ciphertext)

# Decryption
decipher = AES.new(key, AES.MODE_CBC, iv=cipher.iv)
decrypted_text = unpad(decipher.decrypt(ciphertext), AES.block_size)

print('Original message: ', decrypted_text.decode('utf-8'))
