import hashlib
import os
from tkinter import *
from tkinter import filedialog
import tkinter.messagebox as mbox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption, load_pem_public_key, load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.exceptions import InvalidSignature
import base64


def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
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
    mbox.showinfo(title="RSA ključevi", message="RSA ključevi su kreirani", **{"default": mbox.OK})


def generate_aes_key():
    key = get_random_bytes(32)
    key_file_path = "tajni_kljuc.txt"
    with open(key_file_path, "wb") as key_file:
        key_file.write(key)
    mbox.showinfo(title="AES ključ", message="AES ključ je kreiran", **{"default": mbox.OK})


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

    ime_datoteke = os.path.basename(file_path)
    poruka = f"Šifrirani dokument: {ime_datoteke}"
    mbox.showinfo(title="Šifriranje javnim ključem", message=poruka + ".enc", **{"default": mbox.OK})


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

    ime_datoteke = os.path.basename(file_path[:-4])
    poruka = f"Dešifrirani dokument: {ime_datoteke}"
    mbox.showinfo(title="Dešifriranje privatnim ključem", message=poruka, **{"default": mbox.OK})


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

    ime_datoteke = os.path.basename(encrypted_file_path)
    poruka = f"Šifrirani dokument: {ime_datoteke}"
    mbox.showinfo(title="Simetrično šifriranje", message=poruka, **{"default": mbox.OK})


def decrypt_symmetric_aes_with_existing_key(file_path, key_path):
    with open(file_path, "rb") as f:
        nonce, tag, encrypted_data = [f.read(x) for x in (16, 16, -1)]

    with open(key_path, "rb") as key_file:
        key = key_file.read()

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

    decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)

    with open(file_path[:-4], "wb") as f:
        f.write(decrypted_data)

    ime_datoteke = os.path.basename(file_path[:-4])
    poruka = f"Dešifrirani dokument: {ime_datoteke}"
    mbox.showinfo(title="Simetrično dešifriranje", message=poruka, **{"default": mbox.OK})


def create_hash(file_path):
    if os.path.isfile(file_path):
        file_name = os.path.basename(file_path)
        
        hash_value = hashlib.sha256()
        with open(file_path, 'rb') as file:
            while True:
                data = file.read(65536)
                if not data:
                    break
                hash_value.update(data)
        
        hash_hex = hash_value.hexdigest()

        new_file_name = os.path.splitext(file_name)[0] + ".hash.txt"

        with open(new_file_name, 'w') as hash_file:
            hash_file.write(hash_hex)

    poruka = f"SHA-256 Hash spremljen u datoteku: {new_file_name}"
    mbox.showinfo(title="Sažimanje datoteke", message=poruka)


def sign_file(file_path):
    with open('privatni_kljuc.txt', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend(),
        )

    with open(file_path, 'rb') as f:
        payload = f.read()

    signature = base64.b64encode(
        private_key.sign(
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    )
    with open(file_path + ".sig", 'wb') as f:
        f.write(signature)

    ime_datoteke = os.path.basename(file_path)
    poruka = f"Potpisivanje dokumenta {ime_datoteke} dovršeno. Kreiran je potpis {ime_datoteke}.enc"
    mbox.showinfo(title="Potpis dokumenta", message=poruka)


def verify_signature(public_key_path, signature_path, original_file_path):
    with open(public_key_path, 'rb') as f:
        public_key = load_pem_public_key(f.read(), default_backend())

    with open(original_file_path, 'rb') as f:
        payload_contents = f.read()

    with open(signature_path, 'rb') as f:
        signature = base64.b64decode(f.read())

    try:
        public_key.verify(
            signature,
            payload_contents,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        mbox.showinfo(title="Provjera potpisa", message="Potpis je valjan")
    except InvalidSignature as e:
        mbox.showwarning(title="Provjera potpisa", message="Potpis nije valjan")


root = Tk()
root.title("Data Protector by bujin")

for i in range(3):
    root.grid_columnconfigure(i, weight=1)

asymmetric_frame = LabelFrame(root, text="Asimetrično šifriranje - RSA")
asymmetric_frame.grid(row=0, column=0, padx=10, pady=10, sticky='nsew')

generate_keys_button = Button(asymmetric_frame, text="Kreiraj RSA ključeve", command=generate_rsa_keys)
generate_keys_button.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

asymmetric_file_label = Label(asymmetric_frame, text="Odaberi datoteku za šifriranje/dešifriranje:")
asymmetric_file_label.grid(row=1, column=0, padx=10, pady=10)

asymmetric_file_path = StringVar()

def asymmetric_browse_file():
    file_path = filedialog.askopenfilename()
    asymmetric_file_path.set(file_path)

asymmetric_browse_button = Button(asymmetric_frame, text="Pretraži", command=asymmetric_browse_file)
asymmetric_browse_button.grid(row=1, column=1)

asymmetric_encrypt_button = Button(asymmetric_frame, text="Šifriraj", command=lambda: encrypt_asymmetric_rsa(asymmetric_file_path.get()))
asymmetric_encrypt_button.grid(row=2, column=0, padx=10, pady=10)

asymmetric_decrypt_button = Button(asymmetric_frame, text="Dešifriraj", command=lambda: decrypt_asymmetric_rsa(asymmetric_file_path.get()))
asymmetric_decrypt_button.grid(row=2, column=1, padx=10, pady=10)

symmetric_frame = LabelFrame(root, text="Simetrično šifriranje - AES")
symmetric_frame.grid(row=1, column=0, padx=10, pady=10, sticky='nsew')

generate_aes_key_button = Button(symmetric_frame, text="Kreiraj AES ključ", command=generate_aes_key)
generate_aes_key_button.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

symmetric_file_label = Label(symmetric_frame, text="Odaberi datoteku za šifriranje/dešifriranje:")
symmetric_file_label.grid(row=1, column=0, padx=10, pady=10)

symmetric_file_path = StringVar()

def symmetric_browse_file():
    file_path = filedialog.askopenfilename()
    symmetric_file_path.set(file_path)

symmetric_browse_button = Button(symmetric_frame, text="Pretraži", command=symmetric_browse_file)
symmetric_browse_button.grid(row=1, column=1)

symmetric_encrypt_existing_key_button = Button(symmetric_frame, text="Šifriraj", command=lambda: encrypt_symmetric_aes_with_existing_key(symmetric_file_path.get(), "tajni_kljuc.txt"))
symmetric_encrypt_existing_key_button.grid(row=3, column=0, padx=10, pady=10)

symmetric_decrypt_existing_key_button = Button(symmetric_frame, text="Dešifriraj", command=lambda: decrypt_symmetric_aes_with_existing_key(symmetric_file_path.get(), "tajni_kljuc.txt"))
symmetric_decrypt_existing_key_button.grid(row=3, column=1, padx=10, pady=10)

hash_frame = LabelFrame(root, text="Kreiranje sažetka poruke")
hash_frame.grid(row=2, column=0, padx=10, pady=10, sticky='nsew')

hash_file_label = Label(hash_frame, text="Odaberi datoteku za izradu sažetka:")
hash_file_label.grid(row=0, column=0, padx=10, pady=10)

hash_file_path = StringVar()

def hash_browse_file():
    file_path = filedialog.askopenfilename()
    hash_file_path.set(file_path)

hash_browse_button = Button(hash_frame, text="Pretraži", command=hash_browse_file)
hash_browse_button.grid(row=0, column=1)

hash_create_button = Button(hash_frame, text="Kreiraj sažetak", command=lambda: create_hash(hash_file_path.get()))
hash_create_button.grid(row=0, column=2, padx=10, pady=10)

sign_frame = LabelFrame(root, text="Potpisivanje poruke")
sign_frame.grid(row=3, column=0, padx=10, pady=10, sticky='nsew')

signature_file_label = Label(sign_frame, text="Odaberi datoteku za digitalno potpisivanje:")
signature_file_label.grid(row=0, column=0, padx=10, pady=10)

signature_file_path = StringVar()

def signature_browse_file():
    file_path = filedialog.askopenfilename()
    signature_file_path.set(file_path)

signature_browse_button = Button(sign_frame, text="Pretraži", command=signature_browse_file)
signature_browse_button.grid(row=0, column=1)

signature_create_button = Button(sign_frame, text="Potpiši", command=lambda: sign_file(signature_file_path.get()))
signature_create_button.grid(row=0, column=2, padx=10, pady=10)

v_sign_frame = LabelFrame(root, text="Ovjera potpisa")
v_sign_frame.grid(row=4, column=0, padx=10, pady=10, sticky='nsew')

v_original_file_label = Label(v_sign_frame, text="Odaberi izvornu datoteku:")
v_original_file_label.grid(row=1, column=0, padx=10, pady=10)

v_original_file_path = StringVar()

def v_original_browse_file():
    file_path = filedialog.askopenfilename()
    v_original_file_path.set(file_path)

v_original_browse_button = Button(v_sign_frame, text="Izvorna datoteka", command=v_original_browse_file)
v_original_browse_button.grid(row=1, column=2)

v_signed_file_label = Label(v_sign_frame, text="Odaberi potpisanu datoteku:")
v_signed_file_label.grid(row=2, column=0, padx=10, pady=10)

v_signed_file_path = StringVar()

def v_signed_browse_file():
    file_path = filedialog.askopenfilename()
    v_signed_file_path.set(file_path)

v_signed_browse_button = Button(v_sign_frame, text="Potpisana datoteka", command=v_signed_browse_file)
v_signed_browse_button.grid(row=2, column=2)

v_signature_create_button = Button(v_sign_frame, text="Ovjeri potpis", command=lambda: verify_signature('javni_kljuc.txt', v_signed_file_path.get(), v_original_file_path.get()))
v_signature_create_button.grid(row=3, column=2, padx=10, pady=10)

root.mainloop()
