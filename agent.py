import os
import socket
import getpass
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
        os.makedirs(self.agent_folder_path, exist_ok=True)
        self.private_key_file_path = os.path.join(self.agent_folder_path, f"agent{self.agent_id}_private_key.pem")
        self.csr_file_path = os.path.join(self.agent_folder_path, f"agent{self.agent_id}_csr.pem")
        self.signed_cert_file_path = os.path.join(self.agent_folder_path, f"agent{self.agent_id}_signed_cert.pem")
        self.private_key = None

    def check_existing_files(self):
        if os.path.isfile(self.private_key_file_path) and os.path.isfile(self.csr_file_path):
            print(f"Files for agent {self.agent_id} already exist.")
            overwrite = input("Do you want to overwrite the existing files? (y/n): ").lower()
            if overwrite != 'y':
                print("Using the existing files.")
                return True
        return False

    def create_private_key(self):
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
    
    def get_passphrase(self):
        while True:
            pem_passphrase = getpass.getpass("Enter the PEM passphrase: ")
            if len(pem_passphrase) >= 8:
                confirm_passphrase = getpass.getpass("Confirm the PEM passphrase: ")
                if pem_passphrase == confirm_passphrase:
                    return pem_passphrase.encode('utf-8')  # Convert passphrase to bytes
                else:
                    print("Passphrases do not match. Please try again.")
            else:
                print("Passphrase must be at least 8 characters long. Please try again.")

    def load_private_key(self):
        """Load the private key from file."""
        if not self.pem_passphrase:
            # Prompt for PEM passphrase if not already provided
            while True:
                pem_passphrase = getpass.getpass("Enter the PEM passphrase to load the private key: ")
                if len(pem_passphrase) >= 8:
                    self.pem_passphrase = pem_passphrase.encode('utf-8')
                    break
                else:
                    print("Passphrase must be at least 8 characters long. Please try again.")
        
        with open(self.private_key_file_path, "rb") as file:
            private_key = serialization.load_pem_private_key(
                file.read(),
                password=self.pem_passphrase,
                backend=default_backend()
            )
        return private_key

    def get_public_key(self, private_key):
        """Extract public key from the private key."""
        return private_key.public_key()

    def create_csr(self, private_key):
        ### CHANGE THE ATTRIBUTES TO PROMPT WISE
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "PT"),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Lisboa"),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Porto"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "AgentCA"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, f"Agent{self.agent_id}"),
        ]))
        csr = csr.sign(private_key, hashes.SHA256())
        with open(self.csr_file_path, "wb") as file:
            file.write(csr.public_bytes(serialization.Encoding.PEM))
        return csr
    
    def send_csr_to_gateway(self, csr_pem):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(('localhost', 5000))  # Connect to the Gateway server (localhost:5000)

                # Receive the Gateway's certificate
                gateway_cert_data = b""
                while True:
                    chunk = s.recv(1024)
                    gateway_cert_data += chunk
                    if len(chunk) < 1024:  # Assuming this is the end of the certificate data
                        break

                # Save or store the Gateway's certificate
                if gateway_cert_data:
                    gateway_cert = x509.load_pem_x509_certificate(gateway_cert_data)
                    print("Gateway's certificate received successfully.")
                else:
                    raise ValueError("Failed to receive Gateway's certificate.")

                # Send the CSR to the Gateway
                s.sendall(csr_pem)

                # Receive the signed certificate from the Gateway
                signed_cert_data = b""
                while True:
                    chunk = s.recv(1024)
                    signed_cert_data += chunk
                    if len(chunk) < 1024:  # Assuming this is the end of the certificate data
                        break

                if signed_cert_data:
                    return signed_cert_data
                else:
                    raise ValueError("Failed to receive signed certificate from Gateway.")
        except Exception as e:
            print(f"Error communicating with Gateway: {e}")
            return None

    def save_signed_certificate(self, signed_cert):
        if signed_cert:
            with open(self.signed_cert_file_path, "wb") as file:
                file.write(signed_cert)
            print(f"Signed certificate saved to {self.signed_cert_file_path}")
        else:
            print("Failed to receive signed certificate.")

    def generate_session_key(self):
        """Generate a random session key (AES key)."""
        return os.urandom(32)  # AES-256 key
    
    
    def load_peer_public_key_from_cert(self, cert_path):
        """Load the peer's public key from their certificate."""
        with open(cert_path, "rb") as file:
            cert_data = file.read()
        cert = x509.load_pem_x509_certificate(cert_data)
        return cert.public_key()


def main():
    is_off = False  # Variable to control menu display
    while True:
        try:
            agent_id = int(input("Enter the agent ID (between 1 and 4): "))
            if 1 <= agent_id <= 4:
                break
            else:
                print("Invalid input! Please enter an agent ID between 1 and 4.")
        except ValueError:
            print("Invalid input! Please enter a valid integer for the agent ID.")

    agent = Agent(agent_id)

    if not agent.check_existing_files():
        pem_passphrase = agent.get_passphrase()
        agent.pem_passphrase = pem_passphrase

        private_key = agent.create_private_key()
        csr = agent.create_csr(private_key)
        print("Generated CSR")
        print("Sending CSR to Gateway for signing...")
        signed_cert = agent.send_csr_to_gateway(csr.public_bytes(serialization.Encoding.PEM))
        agent.save_signed_certificate(signed_cert)

    # Load the private key for decryption
    agent.private_key = agent.load_private_key()

    while not is_off:
        print("\nAgent Menu:")
        print("[1] - Start Chatting")
        print("[2] - Exit")

        try:
            choice = int(input("Select an option (1-2): "))

            if choice == 1:
                print("\nStarting secure chat...")
                is_off = True  # Disable the menu while chatting
                start_chat(agent, port=5000 + agent.agent_id)
                is_off = False  # Re-Enable the menu while chatting
                break;
            elif choice == 2:
                print("Exiting the menu.")
                break
            else:
                print("Invalid choice! Please select a valid option (1-2).")
        except ValueError:
            print("Invalid input! Please enter a number between 1 and 2.")


if __name__ == "__main__":
    main()
