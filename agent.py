from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import os

#Create private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
)

agent_id = 1
pem_passphrase = b"The deepest secret in the world"

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
file_path = os.path.join(os.getcwd(), f"Agent/agent{agent_id}_private_key.pem")

try:
    with open(file_path, "wb") as file:
        file.write(private_key_pem)
    print(f"Private key saved to {file_path}")
except Exception as e:
    print(f"An error occurred: {e}")

# Generate a CSR
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    # Provide various details about who we are.
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
    x509.NameAttribute(NameOID.COMMON_NAME, "mysite.com"),
])).add_extension(
    x509.SubjectAlternativeName([
        x509.DNSName("mysite.com"),
        x509.DNSName("www.mysite.com"),
        x509.DNSName("subdomain.mysite.com"),
    ]),
    critical=False,
).sign(private_key, hashes.SHA256())

# Write our CSR out to disk.
with open("path/to/csr.pem", "wb") as file:
    file.write(csr.public_bytes(serialization.Encoding.PEM))