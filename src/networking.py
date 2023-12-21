import socket
import os
import time
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from .encryption import *


def listen_for_broadcast(email, existing_contact):
    # Create a UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Set up socket to listen for broadcast messages
    udp_socket.bind(("", 12345))

    print(f"Listening for broadcast messages on port 12345...")

    list = ['f', 'f']

    while True:
        # Receive message
        data, address = udp_socket.recvfrom(1024)  # Buffer size is 1024 bytes
        print(f"Received message from {address}: {data.decode()}")
        if data.decode() == f"ADD CONTACT: {email}":
            return [data.decode(), address]
        else:
            return list
        

def send_cert(ip, public_key):
    print(f"at the start of send_cert, ip = {ip[0]}   and public key = {public_key}")
        # Sender's IP address and port
    sender_ip = ""  # Replace with the sender's IP address
    sender_port = 12345  # Choose any available port

    # File to be sent
    file_path = public_key  # Replace with the path to your file

    # Create socket
    sender_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the receiver
   # receiver_address = (ip, 12345)  # Replace with the receiver's IP address and port
   # sender_socket.connect(receiver_address)
    sender_socket.connect((ip[0], 12345))  # Connect directly using the 'ip' argument as a string

    # Read the file
    with open(file_path, 'rb') as file:
        file_data = file.read()

    # Send the file
    sender_socket.sendall(file_data)

    # Close the socket
    sender_socket.close()

def send(ip, filename, public_key):
    encrypt(filename, public_key)

    # append e to the filename since that's what the encrypt function does to encrypted files
    # ".e" stands for encrypted
    file_path = filename + '.e'

    # Create socket
    sender_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the receiver
    receiver_address = (ip, 12345)
    sender_socket.connect(receiver_address)

    # Read the file
    with open(file_path, 'rb') as file:
        file_data = file.read()

    # Send the file
    sender_socket.sendall(file_data)

    # Close the socket
    sender_socket.close()
    os.remove(file_path)

    print("File send succesfully.")

def receive(public_key, private_key):
    # Receiver's IP address and port
    receiver_ip = ''  # Replace with the receiver's IP address
    receiver_port = 12345  # Choose the same port as the sender

    # Create socket
    receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind socket to the address and port
    receiver_socket.bind((receiver_ip, receiver_port))

    # Listen for incoming connections
    receiver_socket.listen(1)

    print("Waiting for a connection...")
    connection, sender_address = receiver_socket.accept()
    print(f"Connection from {sender_address} established.")

    # Receive the file
    received_data = connection.recv(4096)  # Adjust buffer size as needed

    # Write the received data to a new file
    with open('received_file', 'wb') as file:
        file.write(received_data)

    # Close the connection and socket
    connection.close()
    receiver_socket.close()

    # Unencrypt file
    decrypt('received_file', public_key, private_key)
    return


def broadcast_message(message, port, max_attempts=3, delay=5):
    # Create a UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Enable broadcasting mode
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Broadcast address
    broadcast_address = '<broadcast>'

    attempt = 0
    while attempt < max_attempts:
        try:
            # Send the message to all devices on the network
            udp_socket.sendto(message.encode(), (broadcast_address, port))
            print(f"Broadcast attempt {attempt + 1} successful.")
            break  # Exit the loop if broadcast is successful
        except Exception as e:
            print(f"Broadcast attempt {attempt + 1} failed: {e}")
            time.sleep(delay)  # Wait for 'delay' seconds before retrying
            attempt += 1

    # Close the socket
    udp_socket.close()

def receive_cert():
    # Receiver's IP address and port
    receiver_ip = ""
    receiver_port = 12345# Choose the same port as the sender

    # Create socket
    receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind socket to the address and port
    receiver_socket.bind((receiver_ip, receiver_port))

    # Listen for incoming connections
    receiver_socket.listen(1)

    print("Waiting for a connection...")
    connection, sender_address = receiver_socket.accept()
    print(f"Connection from {sender_address} established.")
    sender_ip_string = sender_address[0]  # Extract the IP address as a string

    # Receive the file
    received_data = connection.recv(4096)  # Adjust buffer size as needed

    # Write the received data to a new file
    with open(sender_ip_string + '.crt', 'wb') as file:
        file.write(received_data)

    # Close the connection and socket
    connection.close()
    receiver_socket.close()

    with open(sender_ip_string + '.crt', 'rb') as cert_file:
        cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())

    serial_number = cert.serial_number
    
    if check_serial(serial_number) == True:
        return sender_ip_string
    else:
        return 'x'
