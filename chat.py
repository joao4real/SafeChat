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
owner_port = None
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

def handle_send(known_peers, session_key, agent_name, end_chat_flag):
    """Handle sending messages in a separate thread."""
    while True:
        message = input()
        if not message:
            continue
            
        if message.lower() == 'exit':
            encrypted_message = encrypt_message(f"{agent_name}: exit", session_key)
            if encrypted_message:
                encoded = encrypted_message.encode('utf-8')
                with lock:
                    for conn, _ in known_peers.values():
                        try:
                            conn.sendall(encoded)
                        except Exception:
                            continue
            print(f"{agent_name}: left the chat.")
            end_chat_flag.set()
            break
        
        # Format and encrypt message
        full_message = f"{agent_name}: {message}"
        encrypted_message = encrypt_message(full_message, session_key)
        if encrypted_message:
            encoded = encrypted_message.encode('utf-8')
            with lock:
                for conn, _ in known_peers.values():
                    try:
                        conn.sendall(encoded)
                    except Exception:
                        continue

def handle_receive(conn, session_key, end_chat_flag, known_peers):
    """Handle receiving messages in a separate thread."""
    while not end_chat_flag.is_set():
        try:
            conn.settimeout(1.0)
            received_data = conn.recv(4096)
            if not received_data:
                continue

            try:
                # Decode the received data
                encoded_message = received_data.decode('utf-8')
                
                # Attempt decryption
                decrypted = decrypt_message(encoded_message, session_key)
                if not decrypted:
                    continue

                if decrypted.lower().endswith('exit'):
                    sender = decrypted.split(':')[0]
                    print(f"{sender} left the chat.")
                    continue

                print(decrypted)  # Print the decrypted message

                # Forward message only if it's not from us
                with lock:
                    for peer_port, (peer_conn, _) in known_peers.items():
                        if peer_conn != conn:
                            try:
                                # Send original encrypted data
                                peer_conn.sendall(received_data)
                            except Exception:
                                continue

            except (UnicodeDecodeError, binascii.Error):
                continue

        except socket.timeout:
            continue
        except socket.error:
            if not end_chat_flag.is_set():
                break

def start_chat(agent, base_port=5001):
    """Implements decentralized secure chat between multiple agents."""
    agent_port = base_port + agent.agent_id
    known_peers = {}  # {port: (conn, cert)}
    
    try:
        # Load certificates
        agent_cert = x509.load_pem_x509_certificate(
            open(agent.signed_cert_file_path, "rb").read())
        agent_private_key = agent.load_private_key()
        print("Certificates loaded successfully")

        # Start listener socket
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        listener.bind(('localhost', agent_port))
        listener.listen(5)
        print(f"Listening on port {agent_port}")

        # Try to join existing chat first
        session_key = None
        for port in range(base_port, base_port + 5):
            if port != agent_port:
                try:
                    peer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    peer_sock.connect(('localhost', port))
                    print(f"Connected to existing chat on port {port}")
                    session_key = join_chat(peer_sock, agent, agent_cert, 
                                          agent_private_key, known_peers)
                    if session_key:
                        break
                except ConnectionRefusedError:
                    continue

        # If no existing chat found, create new one
        if not session_key:
            session_key = os.urandom(32)
            print(f"Created new chat session as first participant")

        # Start message threads
        end_flag = threading.Event()
        chat_threads = []

        # Start send thread
        send_thread = threading.Thread(
            target=handle_send,
            args=(known_peers, session_key, f"Agent{agent.agent_id}", end_flag)
        )
        send_thread.start()
        chat_threads.append(send_thread)

        # Accept new peers
        while not end_flag.is_set():
            try:
                listener.settimeout(1.0)
                conn, addr = listener.accept()
                print(f"New peer connected from {addr}")
                threading.Thread(
                    target=handle_peer_connection,
                    args=(conn, agent, agent_cert, agent_private_key, 
                          known_peers, session_key)
                ).start()
            except socket.timeout:
                continue
            except socket.error as e:
                print(f"Socket error: {e}")
                break

        # Cleanup
        end_flag.set()
        for thread in chat_threads:
            thread.join()
        for peer in known_peers.values():
            peer[0].close()
        listener.close()

    except Exception as e:
        print(f"Chat error: {e}")
        return

def join_chat(conn, agent, agent_cert, agent_private_key, known_peers):
    """Join existing chat session"""
    try:
        # Exchange certificates
        conn.send(agent_cert.public_bytes(encoding=serialization.Encoding.PEM))
        peer_cert_data = conn.recv(4096)
        peer_cert = x509.load_pem_x509_certificate(peer_cert_data)

        if not agent.validate_certificate(peer_cert, agent.gateway_cert):
            print("Peer certificate validation failed")
            conn.close()
            return None

        # Get session key from peer
        peer_public_key = peer_cert.public_key()
        encrypted_key = base64.b64decode(conn.recv(4096))
        session_key = agent_private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Received and decrypted session key from peer")

        # Store peer connection
        peer_port = conn.getpeername()[1]
        known_peers[peer_port] = (conn, peer_cert)
        
        # Start receive thread for this connection
        end_flag = threading.Event()
        threading.Thread(target=handle_receive,
                       args=(conn, session_key, end_flag, known_peers)).start()
        
        return session_key

    except Exception as e:
        print(f"Error joining chat: {e}")
        conn.close()
        return None

def handle_peer_connection(conn, agent, agent_cert, agent_private_key, known_peers, session_key):
    """Handle new peer joining chat"""
    try:
        # Exchange certificates
        conn.send(agent_cert.public_bytes(encoding=serialization.Encoding.PEM))
        peer_cert_data = conn.recv(4096)
        peer_cert = x509.load_pem_x509_certificate(peer_cert_data)

        if not agent.validate_certificate(peer_cert, agent.gateway_cert):
            print("Peer certificate validation failed")
            conn.close()
            return

        # Send session key
        peer_public_key = peer_cert.public_key()
        encrypted_key = peer_public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        conn.send(base64.b64encode(encrypted_key))
        print(f"Sent encrypted session key to new peer")

        # Store peer connection
        peer_port = conn.getpeername()[1]
        known_peers[peer_port] = (conn, peer_cert)

        # Start receive thread for this peer
        end_flag = threading.Event()
        threading.Thread(target=handle_receive,
                       args=(conn, session_key, end_flag, known_peers)).start()

    except Exception as e:
        print(f"Error handling peer connection: {e}")
        conn.close()