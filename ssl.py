import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Function to load the ENC_KEY from agent.env
def load_enckey_from_env(env_file):
    with open(env_file, "r") as f:
        for line in f:
            if line.startswith("ENC_KEY="):
                return line.strip().split("=", 1)[1]
    raise ValueError("ENC_KEY not found in the environment file.")

# Function to decrypt the file secret.enc
def decrypt_file(env_file, encrypted_file):
    try:
        # Load ENC_KEY from agent.env
        enckey = load_enckey_from_env(env_file)

        # Read encrypted file
        with open(encrypted_file, "rb") as f:
            encrypted_data = f.read()

        # Validate OpenSSL-compatible header
        if not encrypted_data.startswith(b"Salted__"):
            raise ValueError("Invalid file format. Missing 'Salted__' header.")

        # Extract salt and ciphertext
        salt = encrypted_data[8:16]
        ciphertext = encrypted_data[16:]

        # Derive Key and IV using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32 + 16,
            salt=salt,
            iterations=10000,
        )
        key_iv = kdf.derive(enckey.encode("utf-8"))
        key = key_iv[:32]
        iv = key_iv[32:]

        # Decrypt data
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS7 padding
        padding_length = padded_plaintext[-1]
        plaintext = padded_plaintext[:-padding_length]

        # Print decrypted data
        print(f"Decrypted Data: {plaintext.decode('utf-8')}")

    except Exception as e:
        print(f"Error: {e}")

# Usage
env_file_path = "agent.env"        # Path to your agent.env file
encrypted_file_path = "secret.enc"  # Path to the encrypted file

decrypt_file(env_file_path, encrypted_file_path)
