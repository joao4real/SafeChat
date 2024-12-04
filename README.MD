# Gateway and Agent System

This project provides a Python-based implementation of a secure communication system between a **Gateway** server and multiple **Agent** clients. The Gateway serves as a Certificate Authority (CA) that issues certificates to the Agents for secure communication.

---

## Project Structure

```
.
|-- Gateway.py
|-- Agent.py
|-- README.md
```

### File Descriptions

#### Gateway.py

The `Gateway.py` file defines the **Gateway** server, which is responsible for:

- Generating or loading its own private key and self-signed certificate.
- Listening for incoming Agent connections over TCP.
- Receiving Certificate Signing Requests (CSRs) from Agents.
- Signing CSRs and sending back signed certificates to Agents.

#### Agent.py

The `Agent.py` file defines an **Agent** client, which performs the following:

- Generates its own private key and CSR.
- Connects to the Gateway to submit its CSR.
- Receives and saves the signed certificate provided by the Gateway.

---

## How It Works

### Gateway

1. **Initialization:**
   - The Gateway checks if its private key and certificate exist. If not, it generates a new private key and self-signed certificate.
2. **Certificate Signing:**
   - The Gateway listens for incoming Agent connections on `localhost:5000`.
   - When an Agent connects, it sends its CSR to the Gateway.
   - The Gateway processes the CSR, generates a signed certificate, and sends it back to the Agent.

### Agent

1. **Setup:**
   - The Agent generates its own private key and CSR.
   - It connects to the Gateway and submits the CSR.
2. **Certificate Reception:**
   - The Agent receives a signed certificate from the Gateway and saves it for future use.

---

## Detailed Code Explanation

### Gateway.py

#### Key Methods

- `check_existing_files()`: Verifies if the private key and certificate files exist.
- `load_existing_certificate_and_key(has_output)`: Loads the existing private key and certificate from disk.
- `create_private_key()`: Generates a new RSA private key and saves it.
- `create_certificate(private_key)`: Creates a self-signed certificate using the private key.
- `sign_csr(csr)`: Signs a Certificate Signing Request (CSR) received from an Agent.
- `run_gateway_server(host, port)`: Starts the Gateway server, listens for incoming connections, and processes CSRs.

#### Usage

To start the Gateway server, simply run:

```bash
python Gateway.py
```

The server will start on `localhost:5000` and handle Agent requests.

### Agent.py

#### Key Methods

- `check_existing_files()`: Checks if private key and CSR files exist.
- `create_private_key()`: Generates a new private key and saves it.
- `create_csr(private_key)`: Generates a CSR using the private key.
- `send_csr_to_gateway(csr_pem)`: Connects to the Gateway, submits the CSR, and retrieves the signed certificate.
- `save_signed_certificate(signed_cert)`: Saves the signed certificate received from the Gateway.
- `get_passphrase()`: Prompts the user to set or confirm a PEM passphrase.

#### Usage

Run the Agent script:

```bash
python Agent.py
```

Follow the prompts to:

1. Set an Agent ID (between 1 and 4).
2. Generate a private key and CSR.
3. Connect to the Gateway and obtain a signed certificate.

---

## Communication Workflow

1. The Gateway initializes and listens on `localhost:5000`.
2. An Agent connects to the Gateway.
3. The Gateway sends its certificate to the Agent for verification.
4. The Agent sends its CSR to the Gateway.
5. The Gateway signs the CSR and returns the signed certificate to the Agent.
6. The Agent saves the signed certificate for secure communication.

---

## Requirements

- Python 3.8 or later
- `cryptography` library
- Zoneinfo (standard in Python 3.9+)

To install required packages:

```bash
pip install cryptography
```

---

## Notes

### Security Considerations

- The private key and certificate files are stored on disk with encryption and must be protected.
- Ensure the PEM passphrase used for encryption is secure.

### Extensibility

- The code is modular and can be extended for additional functionality such as:
  - Certificate revocation.
  - Secure messaging between Gateway and Agents.

---

## Troubleshooting

### Common Issues

- **Port Already in Use**: Ensure no other service is using port `5000`.
- **Permission Denied**: Verify file permissions for the certificate and private key directories.
- **Failed to Connect**: Check if the Gateway is running and accessible on `localhost:5000`.

### Debugging

- Both Gateway and Agent scripts include error handling to print detailed error messages in case of failures.

---

## License

This project is licensed under the MIT License. Feel free to use and modify the code as needed.

---

## Author

Developed by Jorge Gomes, João Macedo, Vasco Baleia, Pedro Duarte, Daniel Ciríaco and Vicente Silva.
This project was developed in the course of Security Engineering and Architecture of the Computer Engineering MSc [MEI]
and Computer and Telecommunications and Computer Engineering [METI] at ISCTE - University Institute of Lisbon 
