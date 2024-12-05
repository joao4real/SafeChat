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
        return os.path.isfile(self.certificate_path) and os.path.isfile(self.private_key_path)

    def load_existing_certificate_and_key(self):
        with open(self.certificate_path, "rb") as cert_file:
            cert_pem = cert_file.read()
        with open(self.private_key_path, "rb") as key_file:
            key_pem = key_file.read()

        certificate = x509.load_pem_x509_certificate(cert_pem)
        private_key = serialization.load_pem_private_key(key_pem, password=self.pem_passphrase)
        return certificate, private_key

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
        os.makedirs(os.path.dirname(self.private_key_path), exist_ok=True)
        with open(self.private_key_path, "wb") as file:
            file.write(private_key_pem)
        return private_key

    def create_certificate(self, private_key):
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
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(tz=ZoneInfo("Europe/Lisbon"))
        ).not_valid_after(
            datetime.now(tz=ZoneInfo("Europe/Lisbon")) + timedelta(days=1825)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        os.makedirs(os.path.dirname(self.certificate_path), exist_ok=True)
        with open(self.certificate_path, "wb") as file:
            file.write(cert.public_bytes(serialization.Encoding.PEM))
        return cert

    def sign_csr(self, csr):
        certificate, private_key = self.load_existing_certificate_and_key()
        signed_cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(certificate.subject)
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
        return signed_cert

def run_gateway_server(host='localhost', port=5000):
    def signal_handler(sig, frame):
        print("\nInterrupt received, shutting down...")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    gateway = Gateway()

    if gateway.check_existing_files():
        certificate, private_key = gateway.load_existing_certificate_and_key()
    else:
        private_key = gateway.create_private_key()
        certificate = gateway.create_certificate(private_key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        try:
            server_socket.bind((host, port))
            server_socket.listen(1)
            print(f"Gateway listening on {host}:{port}")
        except OSError as e:
            print(f"Error: Unable to bind to {host}:{port} ({e})")
            sys.exit(1)

        while True:
            client_socket, client_address = server_socket.accept()
            with client_socket:
                print(f"Connection established with {client_address}")
                try:
                    cert_bytes = certificate.public_bytes(serialization.Encoding.PEM)
                    client_socket.sendall(len(cert_bytes).to_bytes(4, 'big') + cert_bytes)

                    csr_length = int.from_bytes(client_socket.recv(4), 'big')
                    csr_data = client_socket.recv(csr_length)
                    csr = x509.load_pem_x509_csr(csr_data)
                    signed_cert = gateway.sign_csr(csr)
                    signed_cert_bytes = signed_cert.public_bytes(serialization.Encoding.PEM)
                    client_socket.sendall(len(signed_cert_bytes).to_bytes(4, 'big') + signed_cert_bytes)
                except Exception as e:
                    print(f"Error processing request: {e}")

if __name__ == "__main__":
    run_gateway_server()
