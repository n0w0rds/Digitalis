from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64

# Generate a key pair
key = RSA.generate(2048)  # Generate RSA key pair with a key size of 2048 bits
private_key = key.export_key()  # Export private key
public_key = key.publickey().export_key()  # Export public key
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))  # Create PKCS1_OAEP cipher object with public key

# Generate AES key
data = "This is a secret message"
session_key = get_random_bytes(32)  # Generate random 256-bit AES key (32 bytes)
cipher_aes = AES.new(session_key, AES.MODE_GCM)  # Create AES cipher object in GCM mode

# Encrypt the data with the AES key
ciphertext, tag = cipher_aes.encrypt_and_digest(data.encode())  # Encrypt data and get ciphertext and authentication tag

# Encrypt the session key with RSA public key
enc_session_key = cipher_rsa.encrypt(session_key)  # Encrypt AES session key using RSA public key

# Decryption process
# Load private key
private_key = RSA.import_key(private_key)  # Import private key for decryption
cipher_rsa = PKCS1_OAEP.new(private_key)  # Create PKCS1_OAEP cipher object with private key

# Decrypt the session key with RSA private key
session_key = cipher_rsa.decrypt(enc_session_key)  # Decrypt AES session key using RSA private key

# Decrypt the data with the AES key
cipher_aes = AES.new(session_key, AES.MODE_GCM, cipher_aes.nonce)  # Create AES cipher object for decryption with nonce
decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)  # Decrypt ciphertext and verify authentication tag

print('Decrypted data:', decrypted_data.decode())  # Print decrypted data
