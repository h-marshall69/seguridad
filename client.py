import tkinter as tk
import os
from tkinter import filedialog, messagebox, simpledialog

from encryption import HybridEncryption

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Bóveda de Cifrado Híbrido")

        # Crear instancia de la clase HybridEncryption
        self.encryption = HybridEncryption()

        # Configurar clave RSA predeterminada
        self.private_key_pem, self.public_key_pem = self.encryption.generate_rsa_keys()

        # Interfaz de usuario
        self._build_interface()

    def _build_interface(self):
        # Selección del tamaño de clave
        self.key_size_label = tk.Label(self.root, text="Tamaño de clave simétrica (bits):")
        self.key_size_label.pack(pady=5)

        self.key_size_var = tk.StringVar(value="256")
        self.key_size_options = ["128", "192", "256"]
        self.key_size_menu = tk.OptionMenu(self.root, self.key_size_var, *self.key_size_options)
        self.key_size_menu.pack(pady=5)

        # Campo de entrada para la clave simétrica
        self.key_label = tk.Label(self.root, text="Clave Simétrica (opcional, deje vacío para generar aleatoria):")
        self.key_label.pack(pady=5)

        self.key_entry = tk.Entry(self.root, width=50)
        self.key_entry.pack(pady=5)

        # Campo de entrada para el mensaje
        self.message_label = tk.Label(self.root, text="Mensaje a cifrar:")
        self.message_label.pack(pady=5)

        self.message_entry = tk.Entry(self.root, width=50)
        self.message_entry.pack(pady=5)

        # Botón para cifrar el mensaje
        self.encrypt_button = tk.Button(self.root, text="Cifrar Mensaje", command=self.encrypt_message)
        self.encrypt_button.pack(pady=5)

        self.encrypted_data_label = tk.Label(self.root, text="Mensaje Cifrado:")
        self.encrypted_data_label.pack(pady=5)

        self.encrypted_data_text = tk.Text(self.root, height=5, width=50)
        self.encrypted_data_text.pack(pady=5)

        self.encrypted_key_label = tk.Label(self.root, text="Clave Cifrada (RSA):")
        self.encrypted_key_label.pack(pady=5)

        self.encrypted_key_text = tk.Text(self.root, height=5, width=50)
        self.encrypted_key_text.pack(pady=5)

        # Botón para descifrar el mensaje
        self.decrypt_button = tk.Button(self.root, text="Descifrar Mensaje", command=self.decrypt_message)
        self.decrypt_button.pack(pady=5)

        self.decrypted_message_label = tk.Label(self.root, text="Mensaje Descifrado:")
        self.decrypted_message_label.pack(pady=5)

        self.decrypted_message_text = tk.Text(self.root, height=5, width=50)
        self.decrypted_message_text.pack(pady=5)

    def encrypt_message(self):
        try:
            # Obtener datos
            message = self.message_entry.get().encode()
            if not message:
                messagebox.showerror("Error", "Por favor, ingrese un mensaje.")
                return

            # Configurar tamaño de clave simétrica
            key_size = int(self.key_size_var.get())
            self.encryption.key_size = key_size

            # Obtener clave simétrica del usuario o generar aleatoria
            key_input = self.key_entry.get()
            if key_input:
                key = bytes.fromhex(key_input)
                if len(key) * 8 != key_size:
                    messagebox.showerror("Error", f"La clave debe tener {key_size // 8} bytes ({key_size} bits).")
                    return
            else:
                key = os.urandom(key_size // 8)

            # Cifrar mensaje
            encrypted_data, encrypted_key = self.encryption.hybrid_encrypt(message, self.public_key_pem, key)

            # Guardar clave y mensaje cifrado en un archivo
            save_path = filedialog.asksaveasfilename(title="Guardar Mensaje Cifrado", defaultextension=".txt")
            if save_path:
                with open(save_path, 'w') as file:
                    file.write(f"Clave Simétrica: {key.hex()}\n")
                    file.write(f"Mensaje Cifrado: {encrypted_data.hex()}\n")

            # Mostrar resultados en la interfaz
            self.encrypted_data_text.delete(1.0, tk.END)
            self.encrypted_data_text.insert(tk.END, encrypted_data.hex())

            self.encrypted_key_text.delete(1.0, tk.END)
            self.encrypted_key_text.insert(tk.END, encrypted_key.hex())

            messagebox.showinfo("Éxito", "Mensaje cifrado y guardado correctamente.")

        except Exception as e:
            messagebox.showerror("Error", f"Hubo un problema al cifrar el mensaje: {str(e)}")

    def decrypt_message(self):
        try:
            # Obtener datos cifrados
            encrypted_data = bytes.fromhex(self.encrypted_data_text.get(1.0, tk.END).strip())
            encrypted_key = bytes.fromhex(self.encrypted_key_text.get(1.0, tk.END).strip())

            # Descifrar mensaje
            decrypted_message = self.encryption.hybrid_decrypt(encrypted_data, encrypted_key, self.private_key_pem)

            # Mostrar mensaje descifrado
            self.decrypted_message_text.delete(1.0, tk.END)
            self.decrypted_message_text.insert(tk.END, decrypted_message.decode())

        except Exception as e:
            messagebox.showerror("Error", f"Hubo un problema al descifrar el mensaje: {str(e)}")

# Crear la ventana principal
root = tk.Tk()
app = EncryptionApp(root)

# Iniciar la aplicación
root.mainloop()