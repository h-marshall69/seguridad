from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

class HybridEncryption:
    def __init__(self):
        self.key_size = 256  # Tamaño de clave predeterminado (bits)

    # --- Key Generation ---
    def generate_rsa_keys(self):
        """Generate RSA public and private keys."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        # Serialize keys for storage
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_pem, public_pem

    # --- Symmetric Encryption (AES) ---
    def encrypt_with_aes(self, data, key):
        """Encrypt data using AES encryption."""
        iv = os.urandom(16)  # Initialization vector
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return iv + ciphertext

    def decrypt_with_aes(self, ciphertext, key):
        """Decrypt data using AES encryption."""
        iv = ciphertext[:16]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
        return plaintext

    # --- Asymmetric Encryption (RSA) ---
    def encrypt_key_with_rsa(self, key, public_key_pem):
        """Encrypt AES key with RSA public key."""
        public_key = serialization.load_pem_public_key(public_key_pem)
        encrypted_key = public_key.encrypt(
            key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key

    def decrypt_key_with_rsa(self, encrypted_key, private_key_pem):
        """Decrypt AES key with RSA private key."""
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return key

    # --- Main Functionality ---
    def hybrid_encrypt(self, data, public_key_pem, symmetric_key):
        """Encrypt data using hybrid encryption."""
        # Encrypt the data with AES
        encrypted_data = self.encrypt_with_aes(data, symmetric_key)

        # Encrypt the AES key with RSA
        encrypted_key = self.encrypt_key_with_rsa(symmetric_key, public_key_pem)

        return encrypted_data, encrypted_key

    def hybrid_decrypt(self, encrypted_data, encrypted_key, private_key_pem):
        """Decrypt data using hybrid encryption."""
        # Decrypt the AES key with RSA
        aes_key = self.decrypt_key_with_rsa(encrypted_key, private_key_pem)

        # Decrypt the data with AES
        data = self.decrypt_with_aes(encrypted_data, aes_key)

        return data



"""

# --- Example Usage ---
if __name__ == "__main__":
    # Generate RSA keys
    private_key_pem, public_key_pem = generate_rsa_keys()

    # Data to encrypt
    message = b"This is a top-secret message!"

    # Encrypt the data
    encrypted_data, encrypted_key = hybrid_encrypt(message, public_key_pem)
    print("Encrypted Data:", encrypted_data)
    print("Encrypted AES Key:", encrypted_key)

    # Decrypt the data
    decrypted_message = hybrid_decrypt(encrypted_data, encrypted_key, private_key_pem)
    print("Decrypted Message:", decrypted_message.decode())


"""
