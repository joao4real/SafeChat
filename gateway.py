import signal
import socket
import sys
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import os

class Gateway:
    def __init__(self, certificate_path="Gateway/gateway_certificate.pem", private_key_path="Gateway/gateway_private_key.pem", pem_passphrase=b"The deepest secret in the world"):
        self.certificate_path = certificate_path
        self.private_key_path = private_key_path
        self.pem_passphrase = pem_passphrase

    def check_existing_files(self):
        # Check if the certificate and private key files exist
        if os.path.isfile(self.certificate_path) and os.path.isfile(self.private_key_path):
            print("Certificate and private key already exist.")
            return True
        return False

    def load_existing_certificate_and_key(self,has_output):
        # Load the existing certificate
        with open(self.certificate_path, "rb") as cert_file:
            cert_pem = cert_file.read()
            certificate = x509.load_pem_x509_certificate(cert_pem)
        if(has_output==1):
            print("Certificate loaded successfully.")

        # Load the existing private key
        with open(self.private_key_path, "rb") as key_file:
            key_pem = key_file.read()
            private_key = serialization.load_pem_private_key(key_pem, password=self.pem_passphrase)
        if(has_output==1):            
            print("Private key loaded successfully.")
        
        return certificate, private_key

    def create_private_key(self):
        # Create a new private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )

        # Encrypt private key with PEM passphrase
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(self.pem_passphrase)
        )

        # Save the private key to disk
        try:
            os.makedirs(os.path.dirname(self.private_key_path), exist_ok=True)
            with open(self.private_key_path, "wb") as file:
                file.write(private_key_pem)
            print(f"Private key saved to {self.private_key_path}")
        except Exception as e:
            print(f"An error occurred while saving the private key: {e}")

        return private_key

    def create_certificate(self, private_key):
        # Generate the public key from the private key
        public_key = private_key.public_key()

        # Generate a self-signed certificate
        subject = issuer = x509.Name([ 
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "PT"),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Lisboa"),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Sintra"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "GatewayCA"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "Gateway"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(tz=ZoneInfo("Europe/Lisbon"))
        ).not_valid_after(
            datetime.now(tz=ZoneInfo("Europe/Lisbon")) + timedelta(days=1825)  # 5 years
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        # Save the certificate to disk
        try:
            os.makedirs(os.path.dirname(self.certificate_path), exist_ok=True)
            with open(self.certificate_path, "wb") as file:
                file.write(cert.public_bytes(serialization.Encoding.PEM))
            print(f"CA certificate saved to {self.certificate_path}")
        except Exception as e:
            print(f"An error occurred while saving the certificate: {e}")

        return cert

    def sign_csr(self, csr):
        # Load the private key (you may already have a function for this in your class)
        certificate, private_key = self.load_existing_certificate_and_key(0)
        

        # Generate the signed certificate from the CSR
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(certificate.subject)  # Use the Gateway's Subject as Issuer
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(tz=ZoneInfo("Europe/Lisbon")))
            .not_valid_after(datetime.now(tz=ZoneInfo("Europe/Lisbon")) + timedelta(days=1825))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False
            )
            .sign(private_key, hashes.SHA256())
        )

        # Check if certificate is correctly built and return it
        if cert:
            return cert.public_bytes(serialization.Encoding.PEM)
        else:
            print("Error signing the CSR")
            return None

    def load_private_key(self):
        # Load the private key (you may already have a function for this in your class)
        with open(self.private_key_path, "rb") as key_file:
            key_pem = key_file.read()
            private_key = serialization.load_pem_private_key(key_pem, password=self.pem_passphrase)
        return private_key
    # Define a signal handler
    def signal_handler(sig, frame):
        print("Interrupt received, shutting down...")
        sys.exit(0)  # Gracefully exit the program

# Set up the signal handler for SIGINT (Ctrl + C)



def run_gateway_server(host='localhost', port=5000):
    gateway = Gateway()

    # Check if the certificate and private key already exist
    if gateway.check_existing_files():
        # Load existing certificate and private key
        certificate, private_key = gateway.load_existing_certificate_and_key(1)
    else:
        # Create a new private key and certificate
        private_key = gateway.create_private_key()
        certificate = gateway.create_certificate(private_key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(1)
        print(f"Gateway listening on {host}:{port}")

        while True:
            signal.signal(signal.SIGINT, gateway.signal_handler)
            client_socket, client_address = server_socket.accept()
            with client_socket:
                print(f"Connection established with {client_address}")

                try:
                    # Send the Gateway's certificate to the Agent
                    client_socket.sendall(certificate.public_bytes(serialization.Encoding.PEM))

                    # Receive the CSR from the Agent
                    csr_data = b""
                    while True:
                        chunk = client_socket.recv(1024)
                        csr_data += chunk
                        if len(chunk) < 1024:  # Assuming this is the end of the data
                            break

                    if not csr_data:
                        continue

                    # Process the CSR and generate a signed certificate
                    csr = x509.load_pem_x509_csr(csr_data)
                    print("Received CSR from Agent.")
                    signed_cert = gateway.sign_csr(csr)

                    # Send the signed certificate to the Agent
                    client_socket.sendall(signed_cert)
                except Exception as e:
                    print(f"Error processing request: {e}")

# Start the server
if __name__ == "__main__":
    run_gateway_server()
