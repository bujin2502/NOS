import hashlib
from tkinter import *
from tkinter import filedialog
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption, load_pem_public_key, load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
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
    key_file_path = "tajni_kljuc.txt"
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

    print(f"Encryption complete. Encrypted file: {file_path}.enc")

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

    print(f"Decryption complete. Decrypted file: {file_path[:-4]}")

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

    print(f"Decryption complete. Decrypted file: {file_path[:-4]}")

# Create HASH of file
def create_hash(file_path):
    try:
        with open(file_path, 'rb') as file:
            data = file.read()
            sha256_hash = hashlib.sha256(data).hexdigest()
            return sha256_hash
    except Exception as e:
        return f"Error: {str(e)}"

# Function to save the hash to "hash.txt"
def save_hash_to_file(file_path):
    hash_value = create_hash(file_path)
    if hash_value and not hash_value.startswith("Error"):
        with open("hash.txt", 'w') as hash_file:
            hash_file.write(hash_value)
        return f"SHA-256 Hash saved to 'hash.txt': {hash_value}"
    else:
        return hash_value

# Create SIGNATURE of HASH
def signature_hash(file_path):
    with open(file_path, "rb") as f:
        file_data = f.read()

    with open("privatni_kljuc.txt", "rb") as f:
        try:
            private_key = load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        except Exception as e:
            print(f"Failed to load private key from privatni_kljuc.txt: {e}")
            return

    signature = private_key.sign(
        file_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open(file_path + "_.sig", "wb") as f:
        f.write(signature)

    print(f"Signing complete. Signature file: {file_path}_.sig")


# Function to save the hash to "hash.txt"
def save_signature_to_file(file_path):
    print("Hello, World!")


# Create the GUI
root = Tk()
root.title("Zaštitnik podataka by bujin")

# Postavite ravnotežnu težinu kolona za sve frejmove
for i in range(3):
    root.grid_columnconfigure(i, weight=1)

# Asymmetric encryption buttons
asymmetric_frame = LabelFrame(root, text="Asimetrična enkripcija - RSA")
asymmetric_frame.grid(row=0, column=0, padx=10, pady=10, sticky='nsew')

# Generate RSA keys button
generate_keys_button = Button(asymmetric_frame, text="Kreiraj asimetrični RSA ključ", command=generate_rsa_keys)
generate_keys_button.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

asymmetric_file_label = Label(asymmetric_frame, text="Odaberi datoteku za asimetričnu enkripciju/dekripciju:")
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
symmetric_frame = LabelFrame(root, text="Simetrična enkripcija - AES")
symmetric_frame.grid(row=1, column=0, padx=10, pady=10, sticky='nsew')

# Generate AES key button
generate_aes_key_button = Button(symmetric_frame, text="Kreiraj simetrični AES ključ", command=generate_aes_key)
generate_aes_key_button.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

symmetric_file_label = Label(symmetric_frame, text="Odaberi datoteku za simetričnu enkripciju/dekripciju:")
symmetric_file_label.grid(row=1, column=0, padx=10, pady=10)

symmetric_file_path = StringVar()

def symmetric_browse_file():
    file_path = filedialog.askopenfilename()
    symmetric_file_path.set(file_path)

symmetric_browse_button = Button(symmetric_frame, text="Pretraži", command=symmetric_browse_file)
symmetric_browse_button.grid(row=1, column=1)

# Encrypt with symmetric AES using an existing key button
symmetric_encrypt_existing_key_button = Button(symmetric_frame, text="Enkriptiraj", command=lambda: encrypt_symmetric_aes_with_existing_key(symmetric_file_path.get(), "tajni_kljuc.txt"))
symmetric_encrypt_existing_key_button.grid(row=3, column=0, padx=10, pady=10)

# Decrypt with symmetric AES using an existing key button
symmetric_decrypt_existing_key_button = Button(symmetric_frame, text="Dekriptiraj", command=lambda: decrypt_symmetric_aes_with_existing_key(symmetric_file_path.get(), "tajni_kljuc.txt"))
symmetric_decrypt_existing_key_button.grid(row=3, column=1, padx=10, pady=10)

# Hash frame
hash_frame = LabelFrame(root, text="Kreiranje sažetka poruke")
hash_frame.grid(row=2, column=0, padx=10, pady=10, sticky='nsew')

# Label to prompt the user to select a file
hash_file_label = Label(hash_frame, text="Odaberi datoteku za kreiranje sažetka:")
hash_file_label.grid(row=0, column=0, padx=10, pady=10)

# StringVar to store the selected file path
hash_file_path = StringVar()

# Function to open a file dialog and set the selected file path
def hash_browse_file():
    file_path = filedialog.askopenfilename()
    hash_file_path.set(file_path)

# Button to browse and select a file
hash_browse_button = Button(hash_frame, text="Pretraži", command=hash_browse_file)
hash_browse_button.grid(row=0, column=1)

# Button to create and save the hash
hash_create_button = Button(hash_frame, text="Sažmi", command=lambda: print(save_hash_to_file(hash_file_path.get())))
hash_create_button.grid(row=0, column=2, padx=10, pady=10)

# Signing frame
sign_frame = LabelFrame(root, text="Potpis poruke")
sign_frame.grid(row=3, column=0, padx=10, pady=10, sticky='nsew')

# Label to prompt the user to select a file
signature_file_label = Label(sign_frame, text="Odaberi datoteku za digitalno potpisivanje:")
signature_file_label.grid(row=0, column=0, padx=10, pady=10)

# StringVar to store the selected file path
signature_file_path = StringVar()

# Function to open a file dialog and set the selected file path
def signature_browse_file():
    file_path = filedialog.askopenfilename()
    signature_file_path.set(file_path)

# Button to browse and select a file
signature_browse_button = Button(sign_frame, text="Pretraži", command=signature_browse_file)
signature_browse_button.grid(row=0, column=1)

# Button to create and save the signature
signature_create_button = Button(sign_frame, text="Potpiši", command=lambda: signature_hash(signature_file_path.get()))
signature_create_button.grid(row=0, column=2, padx=10, pady=10)

# Run the main loop
root.mainloop()
