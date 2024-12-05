import os
import socket
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding

def decrypt_message(encrypted_message, session_key):
    """Decrypt a message using the session key (AES)."""
    try:
        encrypted_message = base64.b64decode(encrypted_message)
        iv, encrypted_message = encrypted_message[:16], encrypted_message[16:]
        cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
        return decrypted_message.decode('utf-8')
    except Exception as e:
        print(f"Error during decryption: {e}")
        return None

def encrypt_message(message, session_key):
    """Encrypt a message using the session key (AES)."""
    try:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
        return base64.b64encode(iv + encrypted_message)
    except Exception as e:
        print(f"Error during encryption: {e}")
        return None

def start_chat(agent, host='localhost', port=5001):
    """
    Implements secure chat between two agents, using certificates
    and keys dynamically loaded via the agent's configuration.
    """
    print(f"Starting chat at {host}:{port}...")

    try:
        # Load agent's certificate and private key
        with open(agent.signed_cert_file_path, "rb") as cert_file:
            agent_cert = x509.load_pem_x509_certificate(cert_file.read(), backend=default_backend())
        agent_private_key = agent.load_private_key()


        print("Agent certificate and private key loaded successfully.")
    except Exception as e:
        print(f"Error loading certificate or private key: {e}")
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if port == 5001:
            # Server (Agent 1)
            s.bind((host, port))
            s.listen(1)
            print("Waiting for a connection...")
            conn, addr = s.accept()
            print(f"Connection established with {addr}")
        else:
            # Client (Agent 2)
            s.connect((host, 5001))
            conn = s
            print("Connected to Agent 1.")

        with conn:
            # Exchange certificates
            print("Exchanging certificates...")
            conn.send(agent_cert.public_bytes(encoding=serialization.Encoding.PEM))
            peer_cert_data = conn.recv(4096)

            try:
                peer_cert = x509.load_pem_x509_certificate(peer_cert_data, backend=default_backend())
                agent.validate_certificate(peer_cert)
                peer_public_key = peer_cert.public_key()
                print("Peer certificate validated successfully.")
            except Exception as e:
                print(f"Certificate validation error: {e}")
                return

            if port == 5001:
                # Server: Generate and send session key
                session_key = os.urandom(32)
                encrypted_session_key = peer_public_key.encrypt(
                    session_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                conn.send(encrypted_session_key)
                print("Session key sent.")
            else:
                # Client: Receive and decrypt session key
                encrypted_session_key = conn.recv(4096)
                session_key = agent_private_key.decrypt(
                    encrypted_session_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                print("Session key decrypted successfully.")

            # Start secure chat
            print("Secure chat established. Type 'exit' to quit.")
            while True:
                if port == 5001:
                    # Server sends a message
                    message = input("You (Server): ")
                    if message.lower() == 'exit':
                        conn.send(encrypt_message("exit", session_key))
                        print("Chat ended.")
                        break
                    encrypted_message = encrypt_message(message, session_key)
                    conn.send(encrypted_message)

                    # Server receives a message
                    encrypted_response = conn.recv(4096)
                    response = decrypt_message(encrypted_response, session_key)
                    if response.lower() == 'exit':
                        print("Client ended the chat.")
                        break
                    print(f"Client: {response}")
                else:
                    # Client receives a message
                    encrypted_message = conn.recv(4096)
                    message = decrypt_message(encrypted_message, session_key)
                    if message.lower() == 'exit':
                        print("Server ended the chat.")
                        break
                    print(f"Server: {message}")

                    # Client sends a message
                    response = input("You (Client): ")
                    if response.lower() == 'exit':
                        conn.send(encrypt_message("exit", session_key))
                        print("Chat ended.")
                        break
                    encrypted_response = encrypt_message(response, session_key)
                    conn.send(encrypted_response)