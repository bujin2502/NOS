from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption, load_pem_public_key, load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from tkinter import *
from tkinter import filedialog
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

# Generate RSA keys and save them to files
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    with open("privatni_kljuc.txt", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        ))
    with open("javni_kljuc.txt", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        ))

# Generate a new AES key and save it to a separate key file
def generate_aes_key():
    key = get_random_bytes(32)
    key_file_path = "aes_key.txt"
    with open(key_file_path, "wb") as key_file:
        key_file.write(key)

# Encrypt a file using asymmetric encryption with RSA
def encrypt_asymmetric_rsa(file_path):
    with open(file_path, "rb") as f:
        file_data = f.read()

    with open("javni_kljuc.txt", "rb") as f:
        public_key = load_pem_public_key(
            f.read(),
            backend=default_backend()
        )

    encrypted_data = public_key.encrypt(
        file_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(file_path + ".enc", "wb") as f:
        f.write(encrypted_data)

# Decrypt a file using asymmetric encryption with RSA
def decrypt_asymmetric_rsa(file_path):
    with open(file_path, "rb") as f:
        encrypted_data = f.read()

    with open("privatni_kljuc.txt", "rb") as f:
        private_key = load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(file_path[:-4], "wb") as f:
        f.write(decrypted_data)

# Encrypt a file using symmetric encryption with AES and an existing key
def encrypt_symmetric_aes_with_existing_key(file_path, key_path):
    with open(key_path, "rb") as key_file:
        key = key_file.read()

    with open(file_path, "rb") as f:
        file_data = f.read()

    cipher = AES.new(key, AES.MODE_EAX)

    encrypted_data, tag = cipher.encrypt_and_digest(file_data)

    encrypted_file_path = file_path + ".enc"

    with open(encrypted_file_path, "wb") as f:
        [f.write(x) for x in (cipher.nonce, tag, encrypted_data)]

    print(f"Encryption complete. Encrypted file: {encrypted_file_path}")

# Decrypt a file using symmetric encryption with AES and an existing key
def decrypt_symmetric_aes_with_existing_key(file_path, key_path):
    with open(file_path, "rb") as f:
        nonce, tag, encrypted_data = [f.read(x) for x in (16, 16, -1)]

    with open(key_path, "rb") as key_file:
        key = key_file.read()

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

    decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)

    with open(file_path[:-4], "wb") as f:
        f.write(decrypted_data)

# Create the GUI
root = Tk()
root.title("Zaštitnik podataka")

# Asymmetric encryption buttons
asymmetric_frame = LabelFrame(root, text="Asimetrična enkripcija - RSA")
asymmetric_frame.pack(padx=10, pady=10)

# Generate RSA keys button
generate_keys_button = Button(asymmetric_frame, text="Kreiraj RSA ključ", command=generate_rsa_keys)
generate_keys_button.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

asymmetric_file_label = Label(asymmetric_frame, text="Odaberi datoteku za enkripciju/dekripciju:")
asymmetric_file_label.grid(row=1, column=0, padx=10, pady=10)

asymmetric_file_path = StringVar()

def asymmetric_browse_file():
    file_path = filedialog.askopenfilename()
    asymmetric_file_path.set(file_path)

asymmetric_browse_button = Button(asymmetric_frame, text="Pretraži", command=asymmetric_browse_file)
asymmetric_browse_button.grid(row=1, column=1)

# Encrypt with asymmetric RSA button
asymmetric_encrypt_button = Button(asymmetric_frame, text="Enkriptiraj", command=lambda: encrypt_asymmetric_rsa(asymmetric_file_path.get()))
asymmetric_encrypt_button.grid(row=2, column=0, padx=10, pady=10)

# Decrypt with asymmetric RSA button
asymmetric_decrypt_button = Button(asymmetric_frame, text="Dekriptiraj", command=lambda: decrypt_asymmetric_rsa(asymmetric_file_path.get()))
asymmetric_decrypt_button.grid(row=2, column=1, padx=10, pady=10)

# Symmetric encryption buttons
symmetric_frame = LabelFrame(root, text="Simetrična enkripcija - AES")
symmetric_frame.pack(padx=10, pady=10)

# Generate AES key button
generate_aes_key_button = Button(symmetric_frame, text="Kreiraj AES ključ", command=generate_aes_key)
generate_aes_key_button.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

symmetric_file_label = Label(symmetric_frame, text="Odaberi datoteku za enkripciju/dekripciju:")
symmetric_file_label.grid(row=1, column=0, padx=10, pady=10)

symmetric_file_path = StringVar()

def symmetric_browse_file():
    file_path = filedialog.askopenfilename()
    symmetric_file_path.set(file_path)

symmetric_browse_button = Button(symmetric_frame, text="Pretraži", command=symmetric_browse_file)
symmetric_browse_button.grid(row=1, column=1)

# Encrypt with symmetric AES using an existing key button
symmetric_encrypt_existing_key_button = Button(symmetric_frame, text="Enkriptiraj", command=lambda: encrypt_symmetric_aes_with_existing_key(symmetric_file_path.get(), "aes_key.txt"))
symmetric_encrypt_existing_key_button.grid(row=3, column=0, padx=10, pady=10)

# Decrypt with symmetric AES using an existing key button
symmetric_decrypt_existing_key_button = Button(symmetric_frame, text="Dekriptiraj", command=lambda: decrypt_symmetric_aes_with_existing_key(symmetric_file_path.get(), "aes_key.txt"))
symmetric_decrypt_existing_key_button.grid(row=3, column=1, padx=10, pady=10)


# Run the main loop
root.mainloop()