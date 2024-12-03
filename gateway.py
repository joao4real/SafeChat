from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

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

#Generate a self-signed digital certificate



#Store the self-signed digital certificate