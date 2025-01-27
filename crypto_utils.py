# File: crypto_utils.py

import os
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_ssh_public_key, load_pem_private_key
from cryptography.hazmat.backends import default_backend

# Clé publique intégrée (remplacez ceci par votre clé publique générée)
EMBEDDED_PUBLIC_KEY = b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..."  # Remplacez par votre clé publique complète

def generate_key_pair():
    """Génère une nouvelle paire de clés RSA."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Sérialiser la clé privée au format PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Sérialiser la clé publique au format OpenSSH
    public_ssh = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )
    # Ajouter un commentaire
    public_ssh += b' researcher@institution'
    
    return private_pem, public_ssh

def save_keys(private_pem, public_ssh, private_path='id_rsa', public_path='id_rsa.pub'):
    """Sauvegarde les clés générées dans des fichiers."""
    with open(private_path, 'wb') as f:
        f.write(private_pem)
    with open(public_path, 'wb') as f:
        f.write(public_ssh)
    print(f"Paire de clés générée et sauvegardée:\n- Clé privée: {private_path}\n- Clé publique: {public_path}")

def encrypt_file(file_path: str) -> str:
    """Chiffre le fichier spécifié en utilisant la clé publique intégrée.
       Retourne le chemin du fichier chiffré."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Fichier à chiffrer '{file_path}' non trouvé.")
    
    public_key = load_ssh_public_key(EMBEDDED_PUBLIC_KEY, backend=default_backend())
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Taille du bloc sécuritaire pour une clé de 2048 bits avec OAEP+SHA256
    chunk_size = 190
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    
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
    
    encrypted_data = base64.b64encode(b''.join(encrypted_chunks))
    
    output_path = file_path + '.encrypted'
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)
    
    return output_path

def decrypt_file(file_path: str, private_key_path: str) -> str:
    """Déchiffre le fichier spécifié en utilisant la clé privée.
       Retourne le chemin du fichier déchiffré."""
    if not os.path.exists(private_key_path):
        raise FileNotFoundError(f"Clé privée '{private_key_path}' non trouvée.")
    
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Fichier chiffré '{file_path}' non trouvé.")
    
    with open(private_key_path, 'rb') as key_file:
        private_key = load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    
    with open(file_path, 'rb') as f:
        encrypted_data = base64.b64decode(f.read())
    
    # Taille des blocs RSA pour une clé de 2048 bits
    chunk_size = 256
    chunks = [encrypted_data[i:i + chunk_size] for i in range(0, len(encrypted_data), chunk_size)]
    
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
    
    decrypted_data = b''.join(decrypted_chunks)
    
    # Générer le chemin du fichier déchiffré
    if file_path.endswith('.encrypted'):
        output_path = file_path[:-10] + '.decrypted'
    else:
        output_path = file_path + '.decrypted'
    
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)
    
    return output_path
