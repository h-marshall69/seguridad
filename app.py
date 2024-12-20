import tkinter as tk
from tkinter import filedialog, messagebox
import os
from encryption import HybridEncryption
from send_email import send_email  # Asegúrate de que el módulo está correctamente importado

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Hybrid Encryption")
        self.root.geometry("700x600")
        self.root.configure(bg="#f4f4f4")

        self.hybrid = HybridEncryption()

        self.create_widgets()

    def create_widgets(self):
        header_frame = tk.Frame(self.root, bg="#4a90e2", height=80)
        header_frame.pack(fill=tk.X, side=tk.TOP)
        
        tk.Label(header_frame, text="Hybrid Encryption Tool", font=("Arial", 24), bg="#4a90e2", fg="white").pack(pady=20)

        button_frame = tk.Frame(self.root, bg="#f4f4f4")
        button_frame.pack(pady=20)

        button_style = {"font": ("Arial", 14), "bg": "#4a90e2", "fg": "white", "relief": tk.RAISED, "bd": 4, "padx": 10, "pady": 5, 'width': 30}

        tk.Button(button_frame, text="Generar Clave Simétrica", command=self.generate_symmetric_key, **button_style).grid(row=0, column=0, padx=10, pady=10)
        tk.Button(button_frame, text="Cifrar Archivo con AES", command=self.encrypt_with_aes, **button_style).grid(row=1, column=0, padx=10, pady=10)
        tk.Button(button_frame, text="Descifrar Archivo con AES", command=self.decrypt_with_aes, **button_style).grid(row=1, column=1, padx=10, pady=10)
        tk.Button(button_frame, text="Cifrar Clave Simétrica con RSA", command=self.encrypt_key_with_rsa, **button_style).grid(row=2, column=0, padx=10, pady=10)
        tk.Button(button_frame, text="Descifrar Clave Simétrica con RSA", command=self.decrypt_key_with_rsa, **button_style).grid(row=0, column=1, padx=10, pady=10)
        tk.Button(button_frame, text="Generar Claves RSA", command=self.generate_rsa_keys, **button_style).grid(row=2, column=1, padx=10, pady=10)
        tk.Button(button_frame, text="Enviar Clave y Archivo por Email", command=self.send_email_with_attachments, **button_style).grid(row=3, column=0, columnspan=2, padx=10, pady=10)

        # Establecer las filas y columnas para expandirse
        button_frame.grid_rowconfigure(0, weight=1)
        button_frame.grid_rowconfigure(1, weight=1)
        button_frame.grid_rowconfigure(2, weight=1)
        button_frame.grid_rowconfigure(3, weight=1)
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)
        footer_frame = tk.Frame(self.root, bg="#4a90e2", height=40)
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        tk.Label(footer_frame, text="Desarrollado por [Tu Nombre]", font=("Arial", 10), bg="#4a90e2", fg="white").pack(pady=10)

    def generate_rsa_keys(self):
        private_pem, public_pem = self.hybrid.generate_rsa_keys()
        save_path = filedialog.askdirectory(title="Seleccionar Carpeta para Guardar Claves")

        if save_path:
            with open(os.path.join(save_path, "private_key.pem"), "wb") as f:
                f.write(private_pem)
            with open(os.path.join(save_path, "public_key.pem"), "wb") as f:
                f.write(public_pem)
            messagebox.showinfo("Éxito", "Claves RSA generadas y guardadas correctamente.")

    def generate_symmetric_key(self):
        key = self.hybrid.generate_symmetric_key()
        save_path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key files", "*.key")])

        if save_path:
            with open(save_path, "wb") as f:
                f.write(key)
            messagebox.showinfo("Éxito", "Clave simétrica generada y guardada correctamente.")

    def encrypt_with_aes(self):
        key_path = filedialog.askopenfilename(title="Seleccionar Clave Simétrica", filetypes=[("Key files", "*.key")])
        file_path = filedialog.askopenfilename(title="Seleccionar Archivo a Cifrar", filetypes=[("Message files", "*.txt")])
        output_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted files", "*.enc")])

        if key_path and file_path and output_path:
            self.hybrid.encrypt_with_aes(key_path, file_path, output_path)
            messagebox.showinfo("Éxito", f"Archivo cifrado guardado en {output_path}.")

    def decrypt_with_aes(self):
        key_path = filedialog.askopenfilename(title="Seleccionar Clave Simétrica", filetypes=[("Key files", "*.key")])
        encrypted_file_path = filedialog.askopenfilename(title="Seleccionar Archivo Cifrado", filetypes=[("Encrypted files", "*.enc")])
        output_file_path = filedialog.asksaveasfilename(title="Seleccionar Destino para Guardar", defaultextension=".txt")

        if key_path and encrypted_file_path and output_file_path:
            self.hybrid.decrypt_with_aes(key_path, encrypted_file_path, output_file_path)
            messagebox.showinfo("Éxito", f"Archivo descifrado guardado en {output_file_path}.")

    def encrypt_key_with_rsa(self):
        symmetric_key_path = filedialog.askopenfilename(title="Seleccionar Clave Simétrica", filetypes=[("Key files", "*.key")])
        public_key_path = filedialog.askopenfilename(title="Seleccionar Clave Pública", filetypes=[("PEM files", "*.pem")])
        output_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted files", "*.enc")])

        if symmetric_key_path and public_key_path and output_path:
            self.hybrid.encrypt_key_with_rsa(symmetric_key_path, public_key_path, output_path)
            messagebox.showinfo("Éxito", f"Clave simétrica cifrada guardada en {output_path}.")

    def decrypt_key_with_rsa(self):
        encrypted_key_path = filedialog.askopenfilename(title="Seleccionar Clave Cifrada", filetypes=[("Encrypted files", "*.enc")])
        private_key_path = filedialog.askopenfilename(title="Seleccionar Clave Privada", filetypes=[("PEM files", "*.pem")])
        output_path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key files", "*.key")])

        if encrypted_key_path and private_key_path and output_path:
            self.hybrid.decrypt_key_with_rsa(encrypted_key_path, private_key_path, output_path)
            messagebox.showinfo("Éxito", f"Clave descifrada guardada en {output_path}.")

    def send_email_with_attachments(self):
        key_file = filedialog.askopenfilename(title="Seleccionar Clave Cifrada", filetypes=[("Encrypted files", "*.enc")])
        encrypted_file = filedialog.askopenfilename(title="Seleccionar Archivo Cifrado", filetypes=[("Encrypted files", "*.enc")])

        if key_file and encrypted_file:
            subject = "Clave Simétrica y Archivo Cifrados"
            body = "Adjunto encontrarás la clave simétrica cifrada y el archivo cifrado."
            try:
                send_email(subject, body, attachment_path=key_file)
                send_email(subject, body, attachment_path=encrypted_file)
                messagebox.showinfo("Éxito", "Archivos enviados por correo exitosamente.")
            except Exception as e:
                messagebox.showerror("Error", f"Error al enviar el correo: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
