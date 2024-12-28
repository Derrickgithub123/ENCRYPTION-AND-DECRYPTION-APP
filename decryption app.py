import tkinter as tk
from tkinter import messagebox, filedialog
from cryptography.fernet import Fernet


class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Message Encryption/Decryption")

        # Create a frame to hold all widgets
        self.frame = tk.Frame(root, padx=5, pady=5)
        self.frame.pack(padx=5, pady=5)

        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)

        self.label1 = tk.Label(self.frame, text="Enter Message:")
        self.label1.pack()

        self.message_entry = tk.Entry(self.frame, width=80, font=("arial", 14), bg="white")
        self.message_entry.pack(pady=5)

        self.encrypt_button = tk.Button(self.frame, text="Encrypt", command=self.encrypt_message, font=("arial", 14), bg="lightyellow")
        self.encrypt_button.pack()

        self.label2 = tk.Label(self.frame, text="Encrypted Message:")
        self.label2.pack()

        self.encrypted_message = tk.Entry(self.frame, width=80, font=("arial", 14), bg="white")
        self.encrypted_message.pack(pady=10)

        self.decrypt_button = tk.Button(self.frame, text="Decrypt", command=self.decrypt_message, font=("arial", 14), bg="lightyellow")
        self.decrypt_button.pack()

        self.label3 = tk.Label(self.frame, text="Decrypted Message:")
        self.label3.pack()

        self.decrypted_message = tk.Entry(self.frame, width=80, font=("arial", 14), bg="white")
        self.decrypted_message.pack()

        self.clear_button = tk.Button(self.frame, text="Clear", command=self.clear_fields, font=("arial", 14), bg="lightyellow")
        self.clear_button.pack(pady=5)

        self.file_encrypt_button = tk.Button(self.frame, text="Encrypt File", command=self.encrypt_file, font=("arial", 14), bg="lightyellow")
        self.file_encrypt_button.pack(pady=5)

        self.file_decrypt_button = tk.Button(self.frame, text="Decrypt File", command=self.decrypt_file, font=("arial", 14), bg="lightyellow")
        self.file_decrypt_button.pack(pady=5)

    def encrypt_message(self):
        message = self.message_entry.get().encode()
        encrypted_message = self.cipher_suite.encrypt(message)
        self.encrypted_message.delete(0, tk.END)
        self.encrypted_message.insert(0, encrypted_message.decode())

    def decrypt_message(self):
        encrypted_message = self.encrypted_message.get().encode()
        try:
            decrypted_message = self.cipher_suite.decrypt(encrypted_message)
            self.decrypted_message.delete(0, tk.END)
            self.decrypted_message.insert(0, decrypted_message.decode())
        except Exception as e:
            messagebox.showerror("Error", "Invalid encrypted message.")

    def clear_fields(self):
        """Clear all input and output fields."""
        self.message_entry.delete(0, tk.END)
        self.encrypted_message.delete(0, tk.END)
        self.decrypted_message.delete(0, tk.END)

    def encrypt_file(self):
        """Encrypt a file selected by the user."""
        file_path = filedialog.askopenfilename(title="Select File to Encrypt", filetypes=[("Text Files", "*.txt"), ("CSV Files", "*.csv")])
        if file_path:
            if not file_path.endswith(('.txt', '.csv')):
                messagebox.showerror("Error", "Selected file format not supported for encryption.")
                return

            with open(file_path, "rb") as file:
                file_data = file.read()
            encrypted_data = self.cipher_suite.encrypt(file_data)

            # Save encrypted file
            with open(file_path + ".encrypted", "wb") as encrypted_file:
                encrypted_file.write(encrypted_data)
            messagebox.showinfo("Success", "File encrypted successfully!")

    def decrypt_file(self):
        """Decrypt a file selected by the user."""
        file_path = filedialog.askopenfilename(title="Select Encrypted File to Decrypt", filetypes=[("Encrypted Files", "*.encrypted")])
        if file_path:
            # Validate file extension
            if not file_path.endswith('.encrypted'):
                messagebox.showerror("Error", "Selected file format not supported for decryption.")
                return

            with open(file_path, "rb") as file:
                encrypted_data = file.read()
            try:
                decrypted_data = self.cipher_suite.decrypt(encrypted_data)

                # Save decrypted file
                decrypted_file_path = file_path[:-10]  # Remove ".encrypted" from the filename
                with open(decrypted_file_path, "wb") as decrypted_file:
                    decrypted_file.write(decrypted_data)
                messagebox.showinfo("Success", "File decrypted successfully!")
            except Exception as e:
                messagebox.showerror("Error", "Failed to decrypt the file.")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
