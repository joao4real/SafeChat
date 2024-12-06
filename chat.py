import binascii
import os
import socket
import base64
import threading
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding

active_connections = []
public_keys = {}
session_key = None
lock = threading.Lock()

def decrypt_message(encrypted_message, session_key):
    """Decrypt a message using the session key (AES)."""
    try:
        # Ensure we're working with bytes
        if isinstance(encrypted_message, str):
            encrypted_message = encrypted_message.encode('utf-8')
            
        encrypted_bytes = base64.b64decode(encrypted_message)
        iv, ciphertext = encrypted_bytes[:16], encrypted_bytes[16:]
        
        # Create cipher with IV
        cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt to bytes
        decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Try UTF-8 decoding with replacement for invalid bytes
        return decrypted_bytes.decode('utf-8', errors='replace')
        
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
        return base64.b64encode(iv + encrypted_message).decode('utf-8')
    except Exception as e:
        print(f"Error during encryption: {e}")
        return None

def handle_send(conn, session_key, agent_name, end_chat_flag):
    """Handle sending messages in a separate thread."""
    while True:
        message = input()
        if message.lower() == 'exit':
            encrypted_message = encrypt_message(f"{agent_name}: exit", session_key)
            if encrypted_message:
                conn.send(encrypted_message.encode('utf-8'))
            print(f"{agent_name}: left the chat.")
            end_chat_flag.set()
            break
        encrypted_message = encrypt_message(f"{agent_name}: {message}", session_key)
        if encrypted_message:
            with lock:
                for connection in active_connections:
                    connection.send(encrypted_message.encode('utf-8'))

def handle_receive(conn, session_key, end_chat_flag):
    """Handle receiving messages in a separate thread."""
    while True:
        if end_chat_flag.is_set():
            break
        conn.settimeout(1.0)
        try:
            received_data = conn.recv(4096)
            if not received_data:
                continue

            try:
                # Verify it's valid base64 first
                base64.b64decode(received_data)
                
                # Attempt decryption
                message = decrypt_message(received_data, session_key)
                if not message:
                    continue
                    
                if message.lower().endswith('exit'):
                    print(f"{message.split(': ')[0]} left the chat.")
                    end_chat_flag.set()
                    break
                    
                sender, msg = message.split(': ', 1)
                print(f"{sender}: {msg}")
                
                # Forward original encoded message
                with lock:
                    for connection in active_connections:
                        if connection != conn:
                            connection.send(received_data)
                            
            except (ValueError, binascii.Error):
                # Not a valid base64 message
                continue
            except Exception as e:
                print(f"Error processing message: {e}")
                continue
                
        except socket.timeout:
            continue

def start_chat(agent, host='localhost', port=5001):
    """
    Implements secure chat between multiple agents, using certificates
    and keys dynamically loaded via the agent's configuration.
    """
    print(f"Starting chat at {host}:{port}...")

    try:
        # Load agent's certificate and private key
        with open(agent.signed_cert_file_path, "rb") as cert_file:
            agent_cert = x509.load_pem_x509_certificate(cert_file.read(), backend=default_backend())
        agent_private_key = agent.load_private_key()

        print("Agent and gateway certificates loaded successfully.")
    except Exception as e:
        print(f"Error loading certificate or private key: {e}")
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            # Try to connect as a client
            s.connect((host, port))
            conn = s
            print("Connected to the server.")
            is_server = False
        except ConnectionRefusedError:
            print("Connection refused. Starting as server...")
            # If connection fails, start as server
            s.bind((host, port))
            s.listen(5)
            print("Waiting for connections...")
            is_server = True

        if is_server:
            while True:
                conn, addr = s.accept()
                print(f"Connection established with {addr}")
                with lock:
                    active_connections.append(conn)
                threading.Thread(target=handle_client, args=(conn, agent, agent_cert, agent_private_key, is_server)).start()
        else:
            with lock:
                active_connections.append(conn)
            handle_client(conn, agent, agent_cert, agent_private_key, is_server)

def handle_client(conn, agent, agent_cert, agent_private_key, is_server):
    global session_key
    try:
        # Exchange certificates
        print("Exchanging certificates...")
        conn.send(agent_cert.public_bytes(encoding=serialization.Encoding.PEM))
        peer_cert_data = conn.recv(4096)

        try:
            peer_cert = x509.load_pem_x509_certificate(peer_cert_data, backend=default_backend())
            agent.validate_certificate(peer_cert, agent.gateway_cert)
            peer_public_key = peer_cert.public_key()
            print("Peer certificate validated successfully.")
        except Exception as e:
            print(f"Certificate validation error: {e}")
            return

        with lock:
            public_keys[conn] = peer_public_key

        if is_server:
            # Server: Generate and send session key
            with lock:
                if session_key is None:
                    session_key = os.urandom(32)
                for connection, public_key in public_keys.items():
                    encrypted_session_key = public_key.encrypt(
                        session_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    connection.send(base64.b64encode(encrypted_session_key))
                print("Session key sent to all agents.")

        else:
            # Client: Receive and decrypt session key
            encrypted_session_key = base64.b64decode(conn.recv(4096))
            session_key = agent_private_key.decrypt(
                encrypted_session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            ##print("Session key decrypted successfully.")

        # Start secure chat
        print("\nSecure chat established. Type 'exit' to quit.")
        agent_name = f"Agent{agent.agent_id}"

        # Send join message
        join_message = f"System: {agent_name} joined the chat" #o nome do agente que aparece é o do master agent
        encrypted_join = encrypt_message(join_message, session_key)
        if encrypted_join:
            with lock:
                for connection in active_connections:
                    if connection != conn:
                        connection.send(encrypted_join.encode('utf-8'))

        end_chat_flag = threading.Event()
        send_thread = threading.Thread(target=handle_send, args=(conn, session_key, agent_name, end_chat_flag))
        receive_thread = threading.Thread(target=handle_receive, args=(conn, session_key, end_chat_flag))
        send_thread.start()
        receive_thread.start()
        send_thread.join()
        receive_thread.join()
        print("Chat session ended. Returning to menu.")
    finally:
        with lock:
            active_connections.remove(conn)
            del public_keys[conn]
        conn.close()