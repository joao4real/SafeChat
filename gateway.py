from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import os

#Get gateway self-signed certificate, if exists



#if not exists or invalid, create new one



pem_passphrase = b"The deepest secret in the world"

#Create private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
)

#Encrypt private key with PEM passphrase
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(pem_passphrase)
)

#Get public key
public_key = private_key.public_key()

public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print(public_key_pem)

# Write our key to disk for safe keeping
file_path = os.path.join(os.getcwd(), "Gateway/gateway_private_key.pem")

try:
    with open(file_path, "wb") as file:
        file.write(private_key_pem)
    print(f"Private key saved to {file_path}")
except Exception as e:
    print(f"An error occurred: {e}")

#Generate a self-signed digital certificate
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Lisboa"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Sintra"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GatewayCA"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Gateway"),
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
    datetime.now(tz=ZoneInfo("Europe/Lisbon")) + timedelta(days=1825)
).add_extension(
    x509.SubjectAlternativeName([x509.DNSName("localhost")]),
    critical=False,
).sign(private_key, hashes.SHA256())

# Write our certificate to disk for safe keeping
file_path = os.path.join(os.getcwd(), "Gateway/gateway_certificate")

try:
    with open(file_path, "wb") as file:
        file.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"CA certificate saved to {file_path}")
except Exception as e:
    print(f"An error occurred: {e}")

#Validate CSR





