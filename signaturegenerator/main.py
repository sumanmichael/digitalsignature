import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    Encoding,
    PrivateFormat,
    NoEncryption,
    PublicFormat,
)
import argparse
import requests


def generate_key_pair():
    """Generate RSA key pair and save to files"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    public_key = private_key.public_key()

    # Save private key
    with open("private_key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption(),
            )
        )

    # Save public key
    with open("public_key.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
            )
        )


def sign_json(json_file_path, private_key_path):
    """Sign a JSON file using the private key"""
    # Load private key
    with open(private_key_path, "rb") as key_file:
        private_key = load_pem_private_key(key_file.read(), password=None)

    # Read JSON file
    with open(json_file_path, "r") as f:
        json_data = json.load(f)

    # IMPORTANT: Sort the keys to ensure consistent ordering
    json_string = json.dumps(json_data, sort_keys=True, separators=(",", ":"))
    json_bytes = json_string.encode("utf-8")

    print("Python - Content being signed (as string):", json_string)
    print("Python - Content being signed (as bytes):", json_bytes)
    print("Python - Content being signed (hex):", json_bytes.hex())

    # The actual SHA-256 hash that will be signed
    sha256_hash = hashes.Hash(hashes.SHA256())
    sha256_hash.update(json_bytes)
    digest = sha256_hash.finalize()
    print("Python - SHA-256 digest of content (hex):", digest.hex())

    # Create signature
    signature = private_key.sign(
        json_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,  # This is the maximum allowed length
        ),
        hashes.SHA256(),
    )

    # Important: save the actual salt length used for debugging
    print("Python - PSS max salt length:", padding.PSS.MAX_LENGTH)
    print("Python - Signature (hex):", signature.hex())

    # Encode signature in base64
    signature_base64 = base64.b64encode(signature).decode("utf-8")
    print("Python - Signature (base64):", signature_base64)

    # Save exact bytes that were signed
    with open("original_signed_content.bin", "wb") as f:
        f.write(json_bytes)

    return json_data, signature_base64


def main():
    parser = argparse.ArgumentParser(
        description="Digital signature tool for JSON files"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Generate keys command
    _ = subparsers.add_parser("gen", help="Generate new key pair")

    # Sign command
    sign = subparsers.add_parser("sign", help="Sign a JSON file")
    sign.add_argument("-f", "--file", required=True, help="JSON file to sign")
    sign.add_argument(
        "-k",
        "--key",
        default="private_key.pem",
        help="Private key file (default: private_key.pem)",
    )
    sign.add_argument(
        "-o",
        "--output",
        default="payload.json",
        help="Output file (default: payload.json)",
    )

    # Verify command
    verify = subparsers.add_parser(
        "verify", help="Test payload verification with server"
    )
    verify.add_argument(
        "-f",
        "--file",
        default="payload.json",
        help="Payload file to verify (default: payload.json)",
    )
    verify.add_argument(
        "-u",
        "--url",
        default="http://localhost:8080/verify",
        help="Verification server URL",
    )

    args = parser.parse_args()

    if args.command == "gen":
        generate_key_pair()
        print("Keys generated and saved to private_key.pem and public_key.pem")

    elif args.command == "sign":
        json_content, signature = sign_json(args.file, args.key)
        payload = {"content": json_content, "signature": signature}
        with open(args.output, "w") as f:
            json.dump(payload, f, indent=2)
        print(f"JSON file signed and payload saved to {args.output}")

    elif args.command == "verify":
        with open(args.file, "r") as f:
            payload = json.load(f)
        response = requests.post(args.url, json=payload)
        print("Server response:", response.text)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
