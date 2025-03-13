# Digital Signature Demo Project

A simple demonstration of digital signature creation and verification using RSA-PSS signatures.

## Components

- **Signature Generator** (Python)

  - Generates RSA key pairs
  - Signs JSON content using private key
  - Creates signature payloads

- **Signature Verifier** (Java Spring Boot)
  - REST API for signature verification
  - Verifies signatures using public key
  - Returns verification status

## Usage

1. Generate key pair:

```sh
cd signaturegenerator
python main.py gen
```

2. Sign a JSON file:

```sh
python main.py sign -f data.json
```

3. Start verification server:

```sh
cd ../signatureverifier
./mvnw spring-boot:run
```

4. Verify signature:

```sh
cd ../signaturegenerator
python main.py verify
```

## Technologies Used

- Python with cryptography library
- Java Spring Boot
- RSA-PSS digital signatures
