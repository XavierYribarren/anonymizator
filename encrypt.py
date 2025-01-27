import os
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_ssh_public_key, load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey
import base64

def generate_key_pair():
    """Generate a new RSA key pair."""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Get public key
    public_key = private_key.public_key()
    
    # Serialize private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key to OpenSSH format with comment
    public_ssh = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )
    
    # Add comment to public key
    public_ssh = public_ssh + b' barren@laptop'
    
    return private_pem, public_ssh

def encrypt_file(file_path: str, public_key_path: str) -> None:
    try:
        # Read the public key
        with open(public_key_path, 'rb') as key_file:
            public_key = load_ssh_public_key(
                key_file.read(),
                backend=default_backend()
            )
        
        # Read the input file
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # RSA can only encrypt data up to a certain size, so we'll chunk it
        chunk_size = 190  # Safe size for 2048-bit key
        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
        
        # Encrypt each chunk
        encrypted_chunks = []
        for chunk in chunks:
            encrypted_chunk = public_key.encrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_chunks.append(encrypted_chunk)
        
        # Combine and encode the encrypted data
        encrypted_data = base64.b64encode(b''.join(encrypted_chunks))
        
        # Save encrypted file
        output_path = file_path + '.encrypted'
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)
            
        print(f"\nFile encrypted successfully!")
        print(f"Saved as: {os.path.basename(output_path)}")
            
    except Exception as e:
        print(f"\nError: Encryption failed - {str(e)}")

def decrypt_file(file_path: str, private_key_path: str) -> None:
    try:
        # Read the private key
        with open(private_key_path, 'rb') as key_file:
            private_key = load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        
        # Read the encrypted file
        with open(file_path, 'rb') as f:
            encrypted_data = base64.b64decode(f.read())
        
        # RSA encrypted chunks are 256 bytes for 2048-bit key
        chunk_size = 256
        chunks = [encrypted_data[i:i + chunk_size] for i in range(0, len(encrypted_data), chunk_size)]
        
        # Decrypt each chunk
        decrypted_chunks = []
        for chunk in chunks:
            decrypted_chunk = private_key.decrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            decrypted_chunks.append(decrypted_chunk)
        
        # Combine the decrypted data
        decrypted_data = b''.join(decrypted_chunks)
        
        # Save decrypted file
        output_path = file_path.replace('.encrypted', '.decrypted')
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
            
        print(f"\nFile decrypted successfully!")
        print(f"Saved as: {os.path.basename(output_path)}")
            
    except Exception as e:
        print(f"\nError: Decryption failed - {str(e)}")

def print_usage():
    print("\nFile Encryption/Decryption Tool (RSA)")
    print("------------------------------------")
    print("Usage:")
    print("  Generate key pair:  python encrypt.py -g")
    print("  Encrypt:           python encrypt.py -e <file_path> <public_key_path>")
    print("  Decrypt:           python encrypt.py -d <file_path> <private_key_path>")
    print("\nExample:")
    print("  python encrypt.py -g")
    print("  python encrypt.py -e myfile.txt id_rsa.pub")
    print("  python encrypt.py -d myfile.txt.encrypted id_rsa")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    operation = sys.argv[1]

    if operation == '-g':
        # Generate new key pair
        private_key, public_key = generate_key_pair()
        
        # Save keys to files
        with open('id_rsa', 'wb') as f:
            f.write(private_key)
        with open('id_rsa.pub', 'wb') as f:
            f.write(public_key)
            
        print("\nKey pair generated successfully!")
        print("Private key saved as: id_rsa")
        print("Public key saved as: id_rsa.pub")
        print("\nKEEP YOUR PRIVATE KEY SAFE AND NEVER SHARE IT!")
        
    elif operation in ['-e', '-d'] and len(sys.argv) == 4:
        file_path = sys.argv[2]
        key_path = sys.argv[3]

        if not os.path.exists(file_path):
            print(f"\nError: File '{file_path}' not found!")
            sys.exit(1)
        if not os.path.exists(key_path):
            print(f"\nError: Key file '{key_path}' not found!")
            sys.exit(1)

        if operation == '-e':
            encrypt_file(file_path, key_path)
        else:
            decrypt_file(file_path, key_path)
    else:
        print_usage()
        sys.exit(1)