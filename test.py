import json
import sys
import zipfile
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os
from datetime import datetime


def add_json(filename, json_file_path):
    # Load existing data from the JSON file
    try:
        with open(json_file_path, 'r') as json_file:
            data = json.load(json_file)
    except FileNotFoundError:
        # If the file doesn't exist, initialize an empty list
        data = []

    # Add the new filename to the data
    data.append(filename)

    # Save the updated data back to the JSON file
    with open(json_file_path, 'w') as json_file:
        json.dump(data, json_file)

def read_json_first(json_file_path):
    try:
        with open(json_file_path, 'r') as json_file:
            data = json.load(json_file)
            if data:
                return data[0]
            else:
                return None
    except FileNotFoundError:
        return None


def encrypt_and_zip(file_path, recipient_cert, sender_cert):
    add_json(file_path, 'filename.json')

    with open(recipient_cert, 'rb') as cert_file:
        r_cert_data = cert_file.read()

    cert = x509.load_pem_x509_certificate(r_cert_data, default_backend())
    public_key = cert.public_key()

    # read the data
    with open('filename.json', 'rb') as file_to_encrypt:
        plaintext = file_to_encrypt.read()
    # encrypt the data
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # put the data in a new file
    with open('filename.json.e', 'wb') as encrypted_file:
        encrypted_file.write(ciphertext)


    # read the data
    with open(file_path, 'rb') as file_to_encrypt:
        plaintext = file_to_encrypt.read()
    # encrypt the data
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Put the data in a new file
    with open('encrypted.e', 'wb') as encrypted_file:
        encrypted_file.write(ciphertext)


    # HASH THE VALUE OF THE DATA AND ENCRYPT IT WITH THE RECIPIENTS KEY
    # SO THEY CAN CHECK THE HASH BEFORE RUNNING THE FILE
    hashed_data = calculate_sha256(file_path)
    hashed_data_bytes = hashed_data.encode('utf-8')
    with open('hash', 'wb') as encrypted_file:
        encrypted_file.write(hashed_data_bytes)

    with open('hash', 'rb') as file_to_encrypt:
        plaintext = file_to_encrypt.read()
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    

    print("File encrypted successfully.")


    with zipfile.ZipFile('encrypted_zip', 'w') as zipf:
        zipf.write(sender_cert, sender_cert)
        zipf.write('encrypted.e', 'encrypted.e')
        zipf.write('hash', 'hash')
        zipf.write('filename.json.e')

    print("File zipped successfully.")

    #os.remove('message.txt.e')
    os.remove('filename.json.e')
    os.remove('filename.json')
    os.remove('encrypted.e')
    os.remove('hash')




def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as file:
        for byte_block in iter(lambda: file.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def decrypt_and_unzip(zip_file_path, private_key):
    # Get the current date and time
    current_datetime = datetime.now()
    date_time_str = current_datetime.strftime("%Y%m%d_%H%M%S")
    folder_name = f"Folder_{date_time_str}"

    os.mkdir(folder_name)

    # read the encrypted file
    with open(private_key, 'rb') as key_file:
        private_key_data = key_file.read()

    # this one works for the most part
    private_key = x509.load_pem_x509_certificate(
        private_key_data,
        default_backend()
    )

    

    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        with zip_ref.open('encrypted.e') as encrypted_file:
            ciphertext = encrypted_file.read()

        # decrypt the file using the private key
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # plaintext = private_key.decrypt(
        #     ciphertext,
        #     padding.OAEP(
        #         mgf=padding.MGF1(algorithm=hashes.SHA256()),
        #         algorithm=hashes.SHA256(),
        #         label=None
        #     )
        # )
        # save the data of the file to be hashed later
        with zip_ref.open('unencrypted.ue', 'wb') as encrypted_file:
            encrypted_file.write(plaintext)

        # read the encrypted file
        with zip_ref.open('hash', 'rb') as encrypted_file:
            ciphertext = encrypted_file.read()
        # decrypt the file using the private key
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # save the data of the file to be hashed later
        with zip_ref.open('hash', 'wb') as encrypted_file:
            encrypted_file.write(plaintext)

        if not (calculate_sha256(folder_name +'unencrypted.ue') == calculate_sha256(folder_name +'hash')):
            print("hash of the file you recieved is incorrect. returning to main menu...")
            return
        else:
            print('the hash matches. this is truly a glorious day indeed')

        # read the encrypted file
        with zip_ref.open('filename.json.e', 'rb') as encrypted_file:
            ciphertext = encrypted_file.read()
        # decrypt the file using the private key
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        with zip_ref.open('filename.json', 'wb') as encrypted_file:
            encrypted_file.write(ciphertext)
        filename = read_json_first('filename.json')

        #os.rename('unencrypted.ue', filename)


# Example usage:
if __name__ == "__main__":
    decrypt_and_unzip(sys.argv[1], sys.argv[2])
    #encrypt_and_zip(sys.argv[1], sys.argv[2], sys.argv[3])
