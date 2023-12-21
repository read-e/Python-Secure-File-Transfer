from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import hashlib


def decrypt(filename, public_key, private_key):
    with open(public_key, 'rb') as cert_file:
        cert_data = cert_file.read()

    with open(private_key, 'rb') as key_file:
        private_key_data = key_file.read()

    # Load the certificate data and extract the public key
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    public_key = cert.public_key()

    # Load the private key
    private_key = serialization.load_pem_private_key(
        private_key_data,
        password=None,
        backend=default_backend()
    )

    # Read the encrypted file
    with open(filename, 'rb') as encrypted_file:
        ciphertext = encrypted_file.read()

    # Decrypt the file using the private key
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Write the decrypted data to a new file
    with open('decrypted_file', 'wb') as decrypted_file:
        decrypted_file.write(plaintext)

    print("File decrypted successfully.")

def encrypt(filename, public_key):
    with open(public_key, 'rb') as cert_file:
        cert_data = cert_file.read()

    # Load the certificate data and extract the public key
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    public_key = cert.public_key()

    with open(filename, 'rb') as file_to_encrypt:
        plaintext = file_to_encrypt.read()

    # Encrypt the file using the public key
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Write the encrypted data to a new file
    with open(filename + '.e', 'wb') as encrypted_file:
        encrypted_file.write(ciphertext)

    print("File encrypted successfully.")

def check_serial(serial):
    hash = hashlib.sha256(str(serial).encode()).hexdigest()

    with open('src/serial.txt', 'r') as file:
        lines = file.read().splitlines()
        if hash in lines:
            return True
        else:
            return False
