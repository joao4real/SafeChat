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
        # Combine IV and encrypted message, encode once as base64, add newline
        return base64.b64encode(iv + encrypted_message).decode('utf-8') + "\n"
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
                with lock:
                    dead_peers = []
                    for port, (conn, _) in known_peers.items():
                        try:
                            conn.sendall(encrypted_message.encode('utf-8'))
                        except Exception:
                            dead_peers.append(port)
                    
                    # Clean up dead peer connections
                    for port in dead_peers:
                        try:
                            known_peers[port][0].close()
                            del known_peers[port]
                        except Exception:
                            pass
                            
            print(f"{agent_name}: left the chat.")
            end_chat_flag.set()
            break
        
        # Format and encrypt message
        full_message = f"{agent_name}: {message}"
        encrypted_message = encrypt_message(full_message, session_key)
        if encrypted_message:
            with lock:
                dead_peers = []
                for port, (conn, _) in known_peers.items():
                    try:
                        conn.sendall(encrypted_message.encode('utf-8'))
                    except Exception:
                        dead_peers.append(port)
                
                # Clean up dead peer connections
                for port in dead_peers:
                    try:
                        known_peers[port][0].close()
                        del known_peers[port]
                    except Exception:
                        pass

def handle_receive(conn, session_key, end_chat_flag, known_peers):
    """Handle receiving messages in a separate thread."""
    message_buffer = b""
    while not end_chat_flag.is_set():
        try:
            conn.settimeout(1.0)
            received_data = conn.recv(4096)
            if not received_data:
                with lock:
                    for port, (peer_conn, _) in list(known_peers.items()):
                        if peer_conn == conn:
                            peer_conn.close()
                            del known_peers[port]
                            break
                break

            # Add to buffer and process complete messages
            message_buffer += received_data
            
            # Process each complete message
            while b'\n' in message_buffer:
                # Split on newline delimiter
                message, message_buffer = message_buffer.split(b'\n', 1)
                if not message:
                    continue

                try:
                    # Decode base64 message
                    decoded_message = message.decode('utf-8').strip()
                    if not decoded_message:
                        continue

                    # Attempt decryption
                    decrypted = decrypt_message(decoded_message, session_key)
                    if not decrypted:
                        continue

                    # Handle exit message
                    if decrypted.lower().endswith('exit'):
                        sender = decrypted.split(':')[0]
                        print(f"{sender} left the chat.")
                        with lock:
                            for port, (peer_conn, _) in list(known_peers.items()):
                                if peer_conn == conn:
                                    peer_conn.close()
                                    del known_peers[port]
                                    break
                        return

                    # Print valid message
                    print(decrypted)

                    # Forward original encrypted message
                    with lock:
                        dead_peers = []
                        # Forward to all peers except sender
                        for port, (peer_conn, _) in known_peers.items():
                            if peer_conn != conn:
                                try:
                                    # Forward with newline to maintain message boundaries
                                    peer_conn.sendall(message + b'\n')
                                except Exception:
                                    dead_peers.append(port)

                        # Clean up dead peers
                        for port in dead_peers:
                            try:
                                known_peers[port][0].close()
                                del known_peers[port]
                            except Exception:
                                pass

                except (UnicodeDecodeError, binascii.Error):
                    # Skip invalid messages
                    continue
                except Exception as e:
                    print(f"Error processing message: {e}")
                    continue

        except socket.timeout:
            continue
        except socket.error:
            if not end_chat_flag.is_set():
                with lock:
                    for port, (peer_conn, _) in list(known_peers.items()):
                        if peer_conn == conn:
                            peer_conn.close()
                            del known_peers[port]
                            break
                break

def start_chat(agent, base_port=5001):
    """Implements decentralized secure chat between multiple agents."""
    agent_port = base_port + agent.agent_id
    known_peers = {}  # {port: (conn, cert)}
    end_flag = threading.Event()
    chat_threads = []
    
    try:
        # Load certificates
        agent_cert = x509.load_pem_x509_certificate(
            open(agent.signed_cert_file_path, "rb").read())
        agent_private_key = agent.load_private_key()
        print("Certificates loaded successfully")

        # Start listener socket with SO_REUSEADDR option
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            listener.bind(('localhost', agent_port))
        except socket.error as e:
            if e.errno == 98:  # Address already in use
                print("Port is busy, waiting for it to be available...")
                # Try to connect to check if someone is actually listening
                try:
                    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_sock.settimeout(1)
                    test_sock.connect(('localhost', agent_port))
                    test_sock.close()
                    print("Another instance is already running on this port.")
                    return
                except ConnectionRefusedError:
                    # Port is stuck but no one is listening, we can reuse it
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    listener.bind(('localhost', agent_port))
                finally:
                    test_sock.close()
            else:
                raise

        listener.listen(5)
        print(f"Listening on port {agent_port}")

        # Rest of the function remains the same
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

        # Start send thread for this agent
        send_thread = threading.Thread(
            target=handle_send,
            args=(known_peers, session_key, f"Agent{agent.agent_id}", end_flag)
        )
        send_thread.start()
        chat_threads.append(send_thread)

        # Start receive threads for all existing peers
        with lock:
            peers_to_process = list(known_peers.items())
        for port, (conn, _) in peers_to_process:
            receive_thread = threading.Thread(
                target=handle_receive,
                args=(conn, session_key, end_flag, known_peers)
            )
            receive_thread.start()
            chat_threads.append(receive_thread)

        # Accept new peers
        while not end_flag.is_set():
            try:
                listener.settimeout(1.0)
                conn, addr = listener.accept()
                print(f"New peer connected from {addr}")
                peer_thread = threading.Thread(
                    target=handle_peer_connection,
                    args=(conn, agent, agent_cert, known_peers, session_key, chat_threads, end_flag)
                )
                peer_thread.start()
            except socket.timeout:
                continue
            except socket.error as e:
                print(f"Socket error: {e}")
                break

        # Cleanup
        end_flag.set()
        with lock:
            for thread in chat_threads:
                thread.join(timeout=1.0)
            for peer in list(known_peers.values()):
                try:
                    peer[0].close()
                except:
                    pass
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

        # Get session key
        encrypted_key = base64.b64decode(conn.recv(4096))
        session_key = agent_private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Received and decrypted session key")

        # Store initial peer connection using base port
        peer_common_name = peer_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        peer_agent_id = int(peer_common_name.replace('Agent', ''))
        base_peer_port = 5001 + peer_agent_id
        known_peers[base_peer_port] = (conn, peer_cert)

        # Get list of other peers
        peer_list_len = int.from_bytes(conn.recv(4), 'big')
        if peer_list_len > 0:
            peer_list_data = conn.recv(peer_list_len)
            try:
                other_peers = eval(peer_list_data.decode('utf-8'))
                
                # Connect to other peers
                for port in other_peers:
                    if port not in known_peers:
                        try:
                            new_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            new_sock.connect(('localhost', port))
                            print(f"Connecting to peer on port {port}")
                            
                            # Exchange certificates
                            new_sock.send(agent_cert.public_bytes(encoding=serialization.Encoding.PEM))
                            new_peer_cert_data = new_sock.recv(4096)
                            new_peer_cert = x509.load_pem_x509_certificate(new_peer_cert_data)
                            
                            if agent.validate_certificate(new_peer_cert, agent.gateway_cert):
                                # Share session key
                                new_peer_public_key = new_peer_cert.public_key()
                                new_encrypted_key = new_peer_public_key.encrypt(
                                    session_key,
                                    padding.OAEP(
                                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                        algorithm=hashes.SHA256(),
                                        label=None
                                    )
                                )
                                new_sock.send(base64.b64encode(new_encrypted_key))
                                
                                # Send empty peer list to avoid loops
                                new_sock.send((0).to_bytes(4, 'big'))
                                
                                # Store connection
                                known_peers[port] = (new_sock, new_peer_cert)
                                print(f"Successfully connected to peer on port {port}")
                        except Exception as e:
                            print(f"Failed to connect to peer on port {port}: {str(e)}")
            except Exception as e:
                print(f"Warning: Error handling peer list: {str(e)}")

        return session_key

    except Exception as e:
        print(f"Error joining chat: {str(e)}")
        conn.close()
        return None
    
def handle_peer_connection(conn, agent, agent_cert, known_peers, session_key, chat_threads, end_flag):
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

        # Extract agent ID from certificate's common name
        peer_common_name = peer_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        peer_agent_id = int(peer_common_name.replace('Agent', ''))
        base_peer_port = 5001 + peer_agent_id

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

        # Store peer connection using base port
        with lock:
            known_peers[base_peer_port] = (conn, peer_cert)
        
        # Start receive thread for this peer
        receive_thread = threading.Thread(
            target=handle_receive,
            args=(conn, session_key, end_flag, known_peers)
        )
        receive_thread.start()
        chat_threads.append(receive_thread)

        # Send list of other peers
        with lock:
            other_peers = [p for p in known_peers.keys() if p != base_peer_port]
        peer_list_data = str(other_peers).encode('utf-8')
        conn.send(len(peer_list_data).to_bytes(4, 'big'))
        conn.send(peer_list_data)

        print(f"Peer Agent{peer_agent_id} fully connected and initialized")

    except Exception as e:
        print(f"Error handling peer connection: {e}")
        conn.close()