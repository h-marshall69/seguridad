import os
from encryption import HybridEncryption
from send_email import send_email

class EmailSender:
    def __init__(self):
        pass

    def send_encrypted_files(self, subject, body, *files):
        """Método para enviar archivos cifrados por correo."""
        print(f"Enviando correo con los archivos cifrados...")
        for file in files:
            send_email(subject, body, file)
        print("Archivos enviados por correo.")

hybrid_encryption = HybridEncryption()
private_pem, public_pem = hybrid_encryption.generate_rsa_keys()
with open("private_pem.bin", "wb") as f:
    f.write(private_pem)

with open("public_pem.bin", "wb") as f:
    f.write(public_pem)

symmetric_key = hybrid_encryption.generate_symmetric_key()

# Guardar la clave en un archivo binario
with open("symmetric_key.bin", "wb") as f:
    f.write(symmetric_key)
    
hybrid_encryption.encrypt_with_aes("symmetric_key.bin", "example.txt", "example.enc")
hybrid_encryption.encrypt_key_with_rsa("symmetric_key.bin", "other_public_key.pem", "encrypted_symmetric_key.bin")

hybrid_encryption.decrypt_key_with_rsa("encrypted_symmetric_key.bin", "other_private_key.pem", "decrypted_symmetric_key.bin")
hybrid_encryption.decrypt_with_aes("decrypted_symmetric_key.bin", "example.enc", "desencypterexample.txt")

# Enviar los archivos cifrados por correo
email_sender = EmailSender()
subject = "Archivo Cifrado"
body = "Aquí está el archivo cifrado junto con la clave cifrada."
email_sender.send_encrypted_files(subject, body, "example.enc", "encrypted_symmetric_key.bin")