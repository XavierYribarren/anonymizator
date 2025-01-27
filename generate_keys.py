from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_keys():
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Serialize private key
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Generate public key
    public_key = private_key.public_key()
    
    # Serialize public key
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Save the keys to files
    with open('private_key.pem', 'wb') as f:
        f.write(pem_private)
    
    with open('public_key.pem', 'wb') as f:
        f.write(pem_public)
    
    print("Keys generated and saved to 'private_key.pem' and 'public_key.pem'.")

if __name__ == "__main__":
    generate_keys()
