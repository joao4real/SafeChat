import os
import socket
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding

def decrypt_session_key(encrypted_session_key, private_key):
    """Decrypt the session key with the agent's private key."""
    print("Decrypting session key...")
    try:
        session_key = private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Ensure that the session key is 32 bytes long (256 bits)
        if len(session_key) != 32:
            raise ValueError(f"Invalid session key size: {len(session_key)} bytes")
        
        print(f"Decrypted session key: {session_key.hex()}")
        return session_key
    except Exception as e:
        print(f"Error during decryption: {e}")
        raise

def encrypt_session_key(session_key, recipient_public_key):
    """Encrypt the session key with the recipient's public key."""
    print(f"Encrypting session key: {session_key.hex()}")
    return recipient_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_message(encrypted_message, session_key):
    """Decrypt a message using the session key (AES)."""
    encrypted_message = base64.b64decode(encrypted_message)  # Decode from base64 if necessary
    iv, encrypted_message = encrypted_message[:16], encrypted_message[16:]  # IV is the first 16 bytes
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()

    try:
        return decrypted_message.decode('utf-8')
    except UnicodeDecodeError as e:
        print(f"Error decoding message: {e}")
        return decrypted_message  # Return raw bytes if decoding fails

def encrypt_message(message, session_key):
    """Encrypt a message using the session key (AES)."""
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    try:
        encrypted_message = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    except UnicodeEncodeError as e:
        print(f"Error encoding message: {e}")
        encrypted_message = encryptor.update(message) + encryptor.finalize()

    return base64.b64encode(iv + encrypted_message)  # Prepend IV to the message and encode to base64

def load_private_key(file_path, passphrase=None):
    """Load the private key from the PEM file."""
    with open(file_path, "rb") as key_file:
        return load_pem_private_key(
            key_file.read(),
            password=passphrase.encode() if passphrase else None,
            backend=default_backend()
        )

def start_chat(agent, port=5001):
    """Starts the chat after certificate and session key exchange."""
    print(f"Waiting for another agent to join on port {port}...")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            if port == 5001:
                # Agent 1 waits for Agent 2 to connect
                s.bind(('localhost', port))
                s.listen(1)
                print("Waiting for connection...")
                conn, addr = s.accept()
                print(f"Connected to {addr}")
            else:
                # Agent 2 connects to Agent 1
                s.connect(('localhost', 5001))
                conn = s
                print("Connected to Agent 1.")

            with conn:
                # Step 1: Exchange Certificates
                print("Exchanging certificates...")
                with open(agent.signed_cert_file_path, "rb") as file:
                    my_cert_data = file.read()
                
                # Send this agent's certificate
                conn.sendall(my_cert_data)
                
                # Receive the other agent's certificate
                peer_cert_data = b"" 
                while True:
                    chunk = conn.recv(1024)
                    peer_cert_data += chunk
                    if len(chunk) < 1024:  # Assuming this marks the end
                        break
                
                # Load the peer's certificate to extract their public key
                peer_cert = x509.load_pem_x509_certificate(peer_cert_data)
                peer_public_key = peer_cert.public_key()
                print("Certificate exchange successful.")

                # Step 2: Session Key Exchange
                if port == 5001:
                    # Agent 1 generates and encrypts the session key
                    session_key = os.urandom(32)  # AES-256 session key (32 bytes = 256 bits)
                    encrypted_session_key = encrypt_session_key(session_key, peer_public_key)
                    print(f"Agent 1 sent encrypted session key: {base64.b64encode(encrypted_session_key).decode('utf-8')}")
                    conn.sendall(encrypted_session_key)  # Send as bytes (no need to convert to string)
                else:
                    # Agent 2 receives and decrypts the session key
                    encrypted_session_key = conn.recv(2048)
                    print(f"Encrypted session key received: {base64.b64encode(encrypted_session_key).decode('utf-8')}")
                    with open(agent.private_key_file_path, "rb") as key_file:
                        private_key = load_pem_private_key(
                            key_file.read(),
                            password=agent.pem_passphrase,
                            backend=default_backend()
                        )
                    try:
                        session_key = decrypt_session_key(encrypted_session_key, private_key)
                        print(f"Agent 2 decrypted session key: {session_key.hex()}")
                    except Exception as e:
                        print(f"Error in decrypting session key: {e}")
                        return
                
                print("Session established. Start chatting! (type 'exit' to quit)")

                # Step 3: Chat Loop
                while True:
                    if port == 5001:
                        # Agent 1 sends first
                        message = input("You: ")
                        if message.lower() == 'exit':
                            print("Ending chat session.")
                            break
                        conn.sendall(encrypt_message(message, session_key))
                        print(f"Agent 1 sent: {message}")

                        encrypted_response = conn.recv(2048)
                        if not encrypted_response:
                            print("Other agent disconnected.")
                            break
                        print(f"Other Agent: {decrypt_message(encrypted_response, session_key)}")
                    else:
                        # Agent 2 receives first
                        encrypted_message = conn.recv(2048)
                        if not encrypted_message:
                            print("Other agent disconnected.")
                            break
                        print(f"Other Agent: {decrypt_message(encrypted_message, session_key)}")
                        
                        message = input("You: ")
                        if message.lower() == 'exit':
                            print("Ending chat session.")
                            break
                        conn.sendall(encrypt_message(message, session_key))
        except Exception as e:
            print(f"Error occurred during chat: {e}")
