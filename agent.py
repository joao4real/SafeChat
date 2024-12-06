import os
import socket
import getpass
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from chat import start_chat  # Import start_chat from chat.py

class Agent:
    def __init__(self, agent_id, pem_passphrase=None):
        self.agent_id = agent_id
        self.pem_passphrase = pem_passphrase
        self.agent_folder_path = os.path.join(os.getcwd(), f"Agent{self.agent_id}")
        self.private_key_file_path = os.path.join(self.agent_folder_path, f"agent{self.agent_id}_private_key.pem")
        self.csr_file_path = os.path.join(self.agent_folder_path, f"agent{self.agent_id}_csr.pem")
        self.signed_cert_file_path = os.path.join(self.agent_folder_path, f"agent{self.agent_id}_signed_cert.pem")
        self.gateway_cert = None  # Initialize the attribute
        os.makedirs(self.agent_folder_path, exist_ok=True)

    def check_existing_files(self):
        """Check if necessary files already exist."""
        if os.path.isfile(self.private_key_file_path) and os.path.isfile(self.csr_file_path):
            print(f"Files for Agent {self.agent_id} already exist.")
            overwrite = input("Do you want to overwrite the existing files? (y/n): ").lower()
            return overwrite != 'y'
        return False

    def prompt_passphrase(self, confirm=False):
        """Prompt the user for a PEM passphrase."""
        while True:
            passphrase = getpass.getpass("Enter the PEM passphrase: ")
            if len(passphrase) >= 8:
                if confirm:
                    confirm_passphrase = getpass.getpass("Confirm the PEM passphrase: ")
                    if passphrase == confirm_passphrase:
                        return passphrase.encode('utf-8')
                    else:
                        print("Passphrases do not match. Try again.")
                else:
                    return passphrase.encode('utf-8')
            else:
                print("Passphrase must be at least 8 characters long. Try again.")

    def create_private_key(self):
        """Create and save a private key."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(self.pem_passphrase)
        )
        with open(self.private_key_file_path, "wb") as file:
            file.write(private_key_pem)
        return private_key

    def load_private_key(self):
        """Load the private key from a file."""
        if not self.pem_passphrase:
            self.pem_passphrase = self.prompt_passphrase()
        with open(self.private_key_file_path, "rb") as file:
            private_key = serialization.load_pem_private_key(
                file.read(),
                password=self.pem_passphrase,
                backend=default_backend()
            )
        self.fetchGatewayCertificate()
        return private_key

    def create_csr(self, private_key):
        """Create a certificate signing request (CSR)."""
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "PT"),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Lisboa"),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Porto"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "AgentCA"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, f"Agent{self.agent_id}"),
        ])).sign(private_key, hashes.SHA256())
        with open(self.csr_file_path, "wb") as file:
            file.write(csr.public_bytes(serialization.Encoding.PEM))
        return csr
    

    def fetchGatewayCertificate(self):
        """Fetch the Gateway's certificate and store it in the gateway_cert variable."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(('localhost', 5000))
            # Request the Gateway certificate by establishing a handshake
            cert_length = int.from_bytes(s.recv(4), 'big')
            gateway_cert_data = s.recv(cert_length)

            # Parse and store the Gateway certificate
            self.gateway_cert = x509.load_pem_x509_certificate(gateway_cert_data, backend=default_backend())

            print("Gateway's certificate successfully fetched and stored.")



    def send_csr_to_gateway(self, csr_pem):
        """Send the CSR to the Gateway and retrieve the signed certificate."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                

                try:
                    self.fetchGatewayCertificate()
                except Exception as e:
                    print(f"Error fetching Gateway certificate: {e}")
                    return None
                
                s.connect(('localhost', 5000))
                # Send CSR to Gateway
                s.sendall(len(csr_pem).to_bytes(4, 'big') + csr_pem)

                # Receive signed certificate
                cert_length = int.from_bytes(s.recv(4), 'big')
                signed_cert_data = s.recv(cert_length)

                if signed_cert_data:
                    return signed_cert_data
                else:
                    raise ValueError("Signed certificate not received.")
        except Exception as e:
            print(f"Error communicating with Gateway: {e}")
            return None
    
    def validate_certificate(self, peer_cert, gateway_cert):
        """Validate the peer's certificate using the Gateway's certificate."""
        try:
            if gateway_cert is None:
                raise ValueError("Gateway certificate is not available for validation.")

            # Check if the issuer of peer_cert matches the subject of gateway_cert
            if peer_cert.issuer != gateway_cert.subject:
                raise ValueError("Peer certificate was not issued by the trusted Gateway.")

            # Check the validity period of peer_cert
            if peer_cert.not_valid_before_utc > datetime.now(timezone.utc) or peer_cert.not_valid_after_utc < datetime.now(timezone.utc):
                raise ValueError("Peer certificate is not valid at the current time.")

            print("Certificate validated successfully.")
            return True
        except Exception as e:
            print(f"Certificate validation error: {e}")
            return False

    def save_signed_certificate(self, signed_cert):
        """Save the signed certificate to a file."""
        with open(self.signed_cert_file_path, "wb") as file:
            file.write(signed_cert)
        print(f"Signed certificate saved to {self.signed_cert_file_path}")

    def load_peer_public_key_from_cert(self, cert_path):
        """Load peer's public key from their certificate."""
        with open(cert_path, "rb") as file:
            cert_data = file.read()
        cert = x509.load_pem_x509_certificate(cert_data)
        return cert.public_key()
    
    

def main():
    while True:
        try:
            agent_id = int(input("Enter the agent ID (between 1 and 4): "))
            if 1 <= agent_id <= 4:
                break
            else:
                print("Invalid ID! Please enter a number between 1 and 4.")
        except ValueError:
            print("Invalid input! Please enter a valid number.")

    agent = Agent(agent_id)

    if not agent.check_existing_files():
        pem_passphrase = agent.prompt_passphrase(confirm=True)
        agent.pem_passphrase = pem_passphrase
        private_key = agent.create_private_key()
        csr = agent.create_csr(private_key)
        print("CSR generated and sent to Gateway.")
        signed_cert = agent.send_csr_to_gateway(csr.public_bytes(serialization.Encoding.PEM))
        if signed_cert:
            agent.save_signed_certificate(signed_cert)
        else:
            print("Failed to obtain signed certificate from Gateway.")
            return

    private_key = agent.load_private_key()

    while True:
        print("\nAgent Menu:")
        print("[1] - Start Chatting")
        print("[2] - Exit")
        try:
            choice = int(input("Select an option (1-2): "))
            if choice == 1:
                print("Starting secure chat...")
                # Ensure chat does not return to the menu until it's over
                start_chat(agent)  # This should block until the chat ends
                print("You exited from the chat. \nReturning to menu...")  # Once chat ends, return to menu
            elif choice == 2:
                print("Exiting the program.")
                break  # Exit program entirely
            else:
                print("Invalid choice! Please select 1 or 2.")
        except ValueError:
            print("Invalid input! Please enter a valid number.")

if __name__ == "__main__":
    main()
