from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

class HybridEncryption:
    def __init__(self):
        self.key_size = 256  # Tamaño de clave predeterminado (bits)

    def generate_symmetric_key(self, size = 256):
        return os.urandom(size // 8)

    def generate_rsa_keys(self, public_exponent=65537, key_size=2048):
        private_key = rsa.generate_private_key(
            public_exponent,
            key_size
        )
        public_key = private_key.public_key()

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
    
    def encrypt_with_aes(self, key_path, file_path, output_path):
        """Encrypt a file using AES encryption."""
        iv = os.urandom(16)  # Inicialización del vector (IV) para AES
        with open(key_path, 'rb') as f:
            key = f.read()

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))  # Crea el cifrador en modo CFB
        encryptor = cipher.encryptor()

        # Abre el archivo de entrada y el archivo de salida
        with open(file_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            # Escribe el IV en el archivo de salida al principio
            f_out.write(iv)

            # Lee y cifra el archivo en bloques
            while chunk := f_in.read(64 * 1024):  # Leer en bloques de 64KB
                ciphertext = encryptor.update(chunk)
                f_out.write(ciphertext)

            # Finaliza el cifrado
            f_out.write(encryptor.finalize())

        print(f"Archivo cifrado y guardado en: {output_path}")

    def decrypt_with_aes(self, key_path, encrypted_file_path, output_file_path):
        """Decrypt a file using AES decryption."""
        # Abrir el archivo cifrado para lectura

        with open(key_path, 'rb') as f:
            key = f.read()

        with open(encrypted_file_path, 'rb') as f_in, open(output_file_path, 'wb') as f_out:
            # Leer el IV del principio del archivo cifrado
            iv = f_in.read(16)
            
            # Crear el objeto Cipher con el IV y la clave simétrica
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
            decryptor = cipher.decryptor()
            
            # Leer y descifrar el archivo en bloques
            while chunk := f_in.read(64 * 1024):  # Leer en bloques de 64KB
                plaintext = decryptor.update(chunk)
                f_out.write(plaintext)

            # Finalizar el descifrado
            f_out.write(decryptor.finalize())

        print(f"Archivo descifrado y guardado en: {output_file_path}")

    def encrypt_key_with_rsa(self, symmetric_key_path, other_public_key_pem_path, output_path):
        """Cifra la clave simétrica usando RSA y guarda el resultado en un archivo."""

        # Leer la clave simétrica desde el archivo
        with open(symmetric_key_path, 'rb') as f:
            key = f.read()

        # Leer la clave pública desde el archivo PEM
        with open(other_public_key_pem_path, 'rb') as f:
            public_key_pem = f.read()

        # Cargar la clave pública desde el archivo PEM
        public_key = serialization.load_pem_public_key(public_key_pem)

        # Cifrar la clave simétrica usando la clave pública
        encrypted_key = public_key.encrypt(
            key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Mask Generation Function (MGF) con SHA256
                algorithm=hashes.SHA256(),  # Algoritmo de hash usado
                label=None
            )
        )

        # Guardar la clave cifrada en un archivo
        with open(output_path, 'wb') as f:
            f.write(encrypted_key)

    def decrypt_key_with_rsa(self, encrypted_symmetric_key_path, private_key_pem_path, output_path):

        with open(encrypted_symmetric_key_path, 'rb') as f:
            key = f.read()

        with open(private_key_pem_path, 'rb') as f:
            private_key= f.read()

        private_key = serialization.load_pem_private_key(private_key, password=None)
        decrypted_key = private_key.decrypt(
            key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open(output_path, 'wb') as f:
            f.write(decrypted_key)