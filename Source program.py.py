
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from tkinter import *
from tkinter import filedialog, messagebox
import os

class DESCipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DES Encryption and Decryption")
        self.root.geometry("600x500")  # Memperbesar ukuran window untuk menampung elemen tambahan

        # Label dan Entry untuk Key
        Label(root, text="Enter Key (max 8 chars):").pack()
        self.key_entry = Entry(root, show="*")
        self.key_entry.pack()

        # Text box untuk Plaintext
        Label(root, text="Plaintext").pack()
        self.plaintext_box = Text(root, height=5, width=60)
        self.plaintext_box.pack()

        # Text box untuk Ciphertext (untuk menampilkan hasil enkripsi)
        Label(root, text="Ciphertext (Hex)").pack()
        self.ciphertext_box = Text(root, height=5, width=60)
        self.ciphertext_box.pack()

        # Tombol untuk berbagai operasi
        Button(root, text="Encrypt Text", command=self.encrypt_text).pack()
        Button(root, text="Decrypt Text", command=self.decrypt_text).pack()
        Button(root, text="Save Ciphertext", command=self.save_ciphertext).pack()
        Button(root, text="Load File", command=self.load_file).pack()
        Button(root, text="Encrypt File", command=self.encrypt_file).pack()
        Button(root, text="Decrypt File", command=self.decrypt_file).pack()

        # Inisialisasi variabel untuk data file yang di-load
        self.file_data = None

    def des_key(self, key):
        # Menyesuaikan panjang key menjadi 8 karakter
        return key.ljust(8)[:8].encode("utf-8")

    def encrypt_text(self):
        key = self.key_entry.get()
        if not key:
            messagebox.showwarning("Warning", "Please enter a key.")
            return
        plaintext = self.plaintext_box.get("1.0", END).strip().encode("utf-8")
        
        cipher = DES.new(self.des_key(key), DES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))
        
        # Menampilkan hasil enkripsi dalam hex ke kolom ciphertext
        self.ciphertext_box.delete("1.0", END)
        self.ciphertext_box.insert("1.0", ciphertext.hex())

    def decrypt_text(self):
        key = self.key_entry.get()
        if not key:
            messagebox.showwarning("Warning", "Please enter a key.")
            return
        ciphertext = bytes.fromhex(self.ciphertext_box.get("1.0", END).strip())
        
        cipher = DES.new(self.des_key(key), DES.MODE_ECB)
        plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
        
        # Menampilkan hasil dekripsi ke kolom plaintext
        self.plaintext_box.delete("1.0", END)
        self.plaintext_box.insert("1.0", plaintext.decode("utf-8"))

    def save_ciphertext(self):
        ciphertext = self.ciphertext_box.get("1.0", END).strip()
        if not ciphertext:
            messagebox.showwarning("Warning", "No ciphertext to save.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "w") as f:
                f.write(ciphertext)
            messagebox.showinfo("Info", "Ciphertext saved successfully.")

    def load_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, "rb") as f:
                self.file_data = f.read()
            self.plaintext_box.delete("1.0", END)
            self.plaintext_box.insert("1.0", self.file_data.decode("utf-8", errors="ignore"))

    def encrypt_file(self):
        key = self.key_entry.get()
        if not key or self.file_data is None:
            messagebox.showwarning("Warning", "Please enter a key and load a file first.")
            return
        
        cipher = DES.new(self.des_key(key), DES.MODE_ECB)
        encrypted_data = cipher.encrypt(pad(self.file_data, DES.block_size))

        file_path = filedialog.asksaveasfilename(defaultextension=".bin", filetypes=[("Binary files", "*.bin")])
        if file_path:
            with open(file_path, "wb") as f:
                f.write(encrypted_data)
            messagebox.showinfo("Info", "File encrypted and saved successfully.")

    def decrypt_file(self):
        key = self.key_entry.get()
        if not key:
            messagebox.showwarning("Warning", "Please enter a key.")
            return
        file_path = filedialog.askopenfilename(filetypes=[("Binary files", "*.bin")])
        if file_path:
            with open(file_path, "rb") as f:
                encrypted_data = f.read()
            
            cipher = DES.new(self.des_key(key), DES.MODE_ECB)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), DES.block_size)
            
            self.plaintext_box.delete("1.0", END)
            self.plaintext_box.insert("1.0", decrypted_data.decode("utf-8", errors="ignore"))
            messagebox.showinfo("Info", "File decrypted successfully.")

if __name__ == "__main__":
    root = Tk()
    app = DESCipherApp(root)
    root.mainloop()
