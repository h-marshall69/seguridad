import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from encryption import HybridEncryption
import os

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Aplicación de Cifrado Híbrido")

        # Instancia de la clase de cifrado
        self.hybrid_encryption = HybridEncryption()

        # Generar claves RSA del usuario
        self.private_key_pem, self.public_key_pem = self.hybrid_encryption.generate_rsa_keys()

        # Clave pública externa (por defecto ninguna cargada)
        self.external_public_key = None

        # --- Configuración de la Interfaz ---
        self.setup_ui()

    def setup_ui(self):
        # Campo para ingresar mensajes
        self.message_label = tk.Label(self.root, text="Mensaje a cifrar:")
        self.message_label.pack(pady=5)

        self.message_entry = tk.Entry(self.root, width=50)
        self.message_entry.pack(pady=5)

        # Selección de clave simétrica
        self.key_label = tk.Label(self.root, text="Clave simétrica (opcional):")
        self.key_label.pack(pady=5)

        self.key_entry = tk.Entry(self.root, width=50)
        self.key_entry.pack(pady=5)

        # Botón para cargar clave pública externa
        self.load_key_button = tk.Button(self.root, text="Cargar clave pública externa", command=self.load_external_public_key)
        self.load_key_button.pack(pady=5)

        # Botón para cifrar el mensaje
        self.encrypt_button = tk.Button(self.root, text="Cifrar y guardar mensaje", command=self.encrypt_and_save_message)
        self.encrypt_button.pack(pady=5)

        # Botón para cargar y descifrar mensaje
        self.decrypt_button = tk.Button(self.root, text="Cargar y descifrar mensaje", command=self.load_and_decrypt_message)
        self.decrypt_button.pack(pady=5)

        # Campo para mostrar el mensaje descifrado
        self.decrypted_message_label = tk.Label(self.root, text="Mensaje Descifrado:")
        self.decrypted_message_label.pack(pady=5)

        self.decrypted_message_text = tk.Text(self.root, height=5, width=50)
        self.decrypted_message_text.pack(pady=5)

    def load_external_public_key(self):
        """Cargar una clave pública desde un archivo."""
        key_file = filedialog.askopenfilename(title="Seleccionar clave pública", filetypes=[("PEM files", "*.pem")])
        if not key_file:
            return
        try:
            with open(key_file, "rb") as f:
                self.external_public_key = f.read()
            messagebox.showinfo("Éxito", "Clave pública cargada correctamente.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo cargar la clave pública: {str(e)}")

    def encrypt_and_save_message(self):
        """Cifrar un mensaje y guardar los datos en un archivo."""
        message = self.message_entry.get().encode()
        if not message:
            messagebox.showerror("Error", "Por favor, ingrese un mensaje.")
            return

        # Generar o usar la clave simétrica proporcionada
        symmetric_key = self.key_entry.get().encode()
        if not symmetric_key:
            symmetric_key = os.urandom(self.hybrid_encryption.key_size // 8)

        # Usar la clave pública externa si está disponible
        public_key = self.external_public_key if self.external_public_key else self.public_key_pem

        try:
            encrypted_data, encrypted_key = self.hybrid_encryption.hybrid_encrypt(message, public_key, symmetric_key)

            # Guardar en un archivo
            save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
            if not save_path:
                return

            with open(save_path, "w") as f:
                f.write("Mensaje Cifrado:\n")
                f.write(encrypted_data.hex() + "\n")
                f.write("Clave Simétrica Cifrada:\n")
                f.write(encrypted_key.hex() + "\n")

            messagebox.showinfo("Éxito", "El mensaje se ha cifrado y guardado correctamente.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo cifrar el mensaje: {str(e)}")

    def load_and_decrypt_message(self):
        """Cargar un archivo con datos cifrados y descifrar el mensaje."""
        file_path = filedialog.askopenfilename(title="Seleccionar archivo cifrado", filetypes=[("Text files", "*.txt")])
        if not file_path:
            return

        try:
            with open(file_path, "r") as f:
                lines = f.readlines()

            encrypted_data = bytes.fromhex(lines[1].strip())
            encrypted_key = bytes.fromhex(lines[3].strip())

            # Descifrar el mensaje
            decrypted_message = self.hybrid_encryption.hybrid_decrypt(encrypted_data, encrypted_key, self.private_key_pem)

            # Mostrar el mensaje descifrado
            self.decrypted_message_text.delete(1.0, tk.END)
            self.decrypted_message_text.insert(tk.END, decrypted_message.decode())
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo descifrar el mensaje: {str(e)}")

# Crear la ventana principal
root = tk.Tk()
app = EncryptionApp(root)

# Iniciar la aplicación
root.mainloop()
