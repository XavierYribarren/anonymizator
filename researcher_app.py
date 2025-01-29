import sys
import os
import io
import base64
import json
import paramiko 
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QPushButton,
    QVBoxLayout, QHBoxLayout, QTabWidget, QFileDialog, QMessageBox, QPlainTextEdit, QDialog, QInputDialog
)
from PyQt6.QtCore import Qt
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend



CONFIG_FILE = "config.json"  # File to store last used private key path

def save_config(data):
    """Save configuration data to a file."""
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f)


def load_config():
    """Load configuration data from a file."""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}

class DropLabel(QLabel):
    """
    Classe personnalisée pour gérer le drag-and-drop de fichiers.
    """
    def __init__(self, parent=None, callback=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setText("Glissez un fichier ici")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.callback = callback

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls:
                file_path = urls[0].toLocalFile()
                self.setText(f"Fichier reçu:\n{file_path}")
                if self.callback:
                    self.callback(file_path)

class KeyInputDialog(QDialog):
    """
    Boîte de dialogue personnalisée pour que l'utilisateur colle sa clé privée RSA.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Entrer Clé Privée")
        self.setGeometry(150, 150, 500, 300)

        layout = QVBoxLayout()

        label = QLabel("Collez la clé privée RSA ici (format PEM) :")
        layout.addWidget(label)

        self.key_input = QPlainTextEdit()
        layout.addWidget(self.key_input)

        button_layout = QHBoxLayout()
        self.ok_button = QPushButton("OK")
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button = QPushButton("Annuler")
        self.cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)
        layout.addLayout(button_layout)

        self.setLayout(layout)

    def get_key(self):
        return self.key_input.toPlainText().strip()

class EncryptorTab(QWidget):
    """
    Onglet Encryptor : Permet de chiffrer des fichiers en utilisant une clé publique RSA.
    Utilise une approche hybride (AES + RSA) pour gérer de gros fichiers.
    """
    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QVBoxLayout()

        # Input pour la Clé de Chiffrement (Champ de Texte)
        key_layout = QHBoxLayout()
        self.key_input = QPlainTextEdit()
        self.key_input.setPlaceholderText("Collez la clé de chiffrement ici (clé publique au format PEM)")
        self.key_input.setFixedHeight(150)  # Hauteur fixe ajustée
        key_layout.addWidget(self.key_input)

        layout.addLayout(key_layout)

        # Drag-and-Drop pour le Fichier à Chiffrer
        self.drop_label = DropLabel(callback=self.encrypt_file)
        layout.addWidget(self.drop_label)

        # Bouton pour Enregistrer le Fichier Chiffré
        self.save_button = QPushButton("Enregistrer le fichier chiffré")
        self.save_button.clicked.connect(self.save_encrypted_file)
        self.save_button.setEnabled(False)  # Désactivé jusqu'à ce qu'un fichier soit chiffré
        layout.addWidget(self.save_button)

        self.setLayout(layout)

        # Variables pour stocker les données chiffrées et le chemin du fichier
        self.encrypted_data = None
        self.encrypted_path = None

    def encrypt_file(self, file_path):
        key_pem = self.key_input.toPlainText().strip()
        if not key_pem:
            QMessageBox.warning(self, "Clé Manquante", "Veuillez coller une clé de chiffrement avant de chiffrer un fichier.")
            return

        # Charger la clé publique
        try:
            public_key = serialization.load_pem_public_key(key_pem.encode('utf-8'), backend=default_backend())
        except Exception as e:
            QMessageBox.critical(self, "Erreur de Clé", f"Impossible de charger la clé de chiffrement.\nErreur: {str(e)}")
            return

        # Lire le contenu du fichier
        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except Exception as e:
            QMessageBox.critical(self, "Erreur de Fichier", f"Impossible de lire le fichier.\nErreur: {str(e)}")
            return

        # Générer une clé symétrique AES
        try:
            aes_key = os.urandom(32)  # AES-256
            iv = os.urandom(16)       # Initialisation Vector
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(data) + encryptor.finalize()
        except Exception as e:
            QMessageBox.critical(self, "Erreur AES", f"Impossible de chiffrer les données avec AES.\nErreur: {str(e)}")
            return

        # Chiffrer la clé AES avec la clé publique RSA
        try:
            encrypted_aes_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            QMessageBox.critical(self, "Erreur RSA", f"Impossible de chiffrer la clé AES avec RSA.\nErreur: {str(e)}")
            return

        # Combiner la clé chiffrée, l'IV et les données chiffrées
        try:
            self.encrypted_data = encrypted_aes_key + iv + encrypted_data
            self.encrypted_path = file_path
            self.drop_label.setText(f"Fichier reçu:\n{file_path}\nChiffrement réussi !")
            self.save_button.setEnabled(True)
        except Exception as e:
            QMessageBox.critical(self, "Erreur de Combinaison", f"Impossible de combiner les données chiffrées.\nErreur: {str(e)}")
            return

    def save_encrypted_file(self):
        if not self.encrypted_data or not self.encrypted_path:
            QMessageBox.warning(self, "Données Manquantes", "Aucune donnée chiffrée à enregistrer.")
            return

        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "Enregistrer le fichier chiffré",
            self.encrypted_path + ".enc",
            "Fichiers Chiffrés (*.enc);;Tous les fichiers (*)"
        )
        if save_path:
            try:
                with open(save_path, "wb") as f:
                    f.write(self.encrypted_data)
                QMessageBox.information(self, "Succès", f"Fichier chiffré enregistré avec succès !\nChemin: {save_path}")
            except Exception as e:
                QMessageBox.critical(self, "Erreur d'Enregistrement", f"Impossible d'enregistrer le fichier chiffré.\nErreur: {str(e)}")

class DecryptorTab(QWidget):
    """
    Onglet Decryptor : Permet de déchiffrer des fichiers chiffrés avec une clé privée RSA.
    Donne le choix entre générer une nouvelle paire de clés ou en charger une existante.
    """
    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QVBoxLayout()

        # Options pour gérer les clés RSA
        key_options_layout = QHBoxLayout()

        # Bouton pour Générer une Paire de Clés
        self.generate_keys_button = QPushButton("Générer une nouvelle paire de clés RSA")
        self.generate_keys_button.clicked.connect(self.generate_keys)
        key_options_layout.addWidget(self.generate_keys_button)

        # Bouton pour Charger une Paire de Clés
        self.load_keys_button = QPushButton("Charger une paire de clés existante")
        self.load_keys_button.clicked.connect(self.load_keys)
        key_options_layout.addWidget(self.load_keys_button)

        layout.addLayout(key_options_layout)
        # Bouton pour oublier les clés
        self.forget_keys_button = QPushButton("Oublier les clés")
        self.forget_keys_button.clicked.connect(self.forget_keys)
        key_options_layout.addWidget(self.forget_keys_button)


        # Affichage des Clés Générées ou Chargées
        keys_layout = QHBoxLayout()

        # Clé Privée
        private_key_layout = QVBoxLayout()
        private_key_label = QLabel("Clé Privée (à conserver secrète) :")
        self.private_key_display = QPlainTextEdit()
        self.private_key_display.setReadOnly(True)
        self.private_key_display.setPlaceholderText("Votre clé privée RSA s'affichera ici...")
        self.private_key_display.setFixedHeight(200)
        private_key_layout.addWidget(private_key_label)
        private_key_layout.addWidget(self.private_key_display)
        keys_layout.addLayout(private_key_layout)

        # Clé Publique
        public_key_layout = QVBoxLayout()
        public_key_label = QLabel("Clé Publique (à partager) :")
        self.public_key_display = QPlainTextEdit()
        self.public_key_display.setReadOnly(True)
        self.public_key_display.setPlaceholderText("Votre clé publique RSA s'affichera ici...")
        self.public_key_display.setFixedHeight(200)
        public_key_layout.addWidget(public_key_label)
        public_key_layout.addWidget(self.public_key_display)
        keys_layout.addLayout(public_key_layout)

        layout.addLayout(keys_layout)

        # Drag-and-Drop pour le Fichier à Déchiffrer
        self.drop_label = DropLabel(callback=self.decrypt_file)
        layout.addWidget(self.drop_label)

        self.setLayout(layout)

        # Variable pour stocker la clé privée chargée ou générée
        self.private_key = None

    def generate_keys(self):
        """
        Générer une nouvelle paire de clés RSA et les afficher.
        """
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            public_key = private_key.public_key()

            # Obtenir les clés au format PEM
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')

            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            # Afficher les clés dans les champs de texte
            self.private_key_display.setPlainText(private_pem)
            self.public_key_display.setPlainText(public_pem)

            # Stocker la clé privée pour une utilisation ultérieure
            self.private_key = private_key

            QMessageBox.information(
                self,
                "Succès",
                "Paire de clés RSA générée avec succès !\nVous pouvez copier les clés depuis les champs ci-dessus."
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Erreur de Génération",
                f"Impossible de générer la paire de clés.\nErreur: {str(e)}"
            )


    def load_keys(self):
        """
        Charger une clé privée RSA existante et récupérer la clé publique correspondante.
        """
        config = load_config()
        private_key_path = config.get("private_key_path", "")

        # Vérifier si l'utilisateur a oublié la clé précédemment
        if not private_key_path:
            print("[DEBUG] Aucune clé enregistrée, l'utilisateur doit en sélectionner une manuellement.")
            private_key_path, _ = QFileDialog.getOpenFileName(
                self,
                "Sélectionner une clé privée",
                "",
                "Clés privées (*.pem *.key *id_rsa);;Tous les fichiers (*)"
            )
            if not private_key_path:
                QMessageBox.warning(self, "Clé Privée Manquante", "Veuillez sélectionner une clé privée.")
                return
        else:
            # Demander si on veut charger la clé enregistrée
            use_saved_key, ok = QInputDialog.getItem(
                self,
                "Utiliser la clé enregistrée ?",
                f"Une clé privée est déjà enregistrée :\n{private_key_path}\nVoulez-vous l'utiliser ?",
                ["Oui", "Non, choisir une autre"],
                0,
                False
            )

            if ok and use_saved_key == "Oui":
                print(f"[DEBUG] Chargement de la clé privée enregistrée : {private_key_path}")
            else:
                private_key_path, _ = QFileDialog.getOpenFileName(
                    self,
                    "Sélectionner une nouvelle clé privée",
                    "",
                    "Clés privées (*.pem *.key *id_rsa);;Tous les fichiers (*)"
                )
                if not private_key_path:
                    QMessageBox.warning(self, "Clé Privée Manquante", "Veuillez sélectionner une clé privée.")
                    return

        print(f"[DEBUG] Clé privée sélectionnée: {private_key_path}")

        try:
            with open(private_key_path, "rb") as f:
                private_pem = f.read()

            # Détection OpenSSH et conversion en PEM
            if private_pem.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"):
                print("[DEBUG] Clé détectée au format OpenSSH. Conversion en PEM en cours...")
                try:
                    private_key = paramiko.RSAKey(filename=private_key_path)

                    private_pem_buffer = io.StringIO()
                    private_key.write_private_key(private_pem_buffer)

                    private_pem = private_pem_buffer.getvalue().encode("utf-8")
                    print("[DEBUG] Conversion réussie !")

                except Exception as e:
                    QMessageBox.critical(self, "Erreur de Conversion", f"Impossible de convertir la clé OpenSSH en PEM.\nErreur: {str(e)}")
                    return
            else:
                print("[DEBUG] Clé déjà au format PEM.")

            # Vérifier si la clé est chiffrée
            if b"ENCRYPTED" in private_pem:
                print("[DEBUG] Clé détectée comme chiffrée, demande de mot de passe...")
                password, ok = QInputDialog.getText(
                    self,
                    "Mot de Passe",
                    "Entrez le mot de passe pour la clé privée (laisser vide si non protégé) :",
                    QInputDialog.InputMode.Normal
                )
                if not ok:
                    return
            else:
                print("[DEBUG] Clé non chiffrée, chargement direct.")
                password = None

            # Charger la clé privée
            try:
                self.private_key = serialization.load_pem_private_key(
                    private_pem,
                    password=password.encode('utf-8') if password else None,
                    backend=default_backend()
                )
                print("[DEBUG] Clé privée chargée avec succès")
            except ValueError as ve:
                QMessageBox.critical(self, "Erreur de Mot de Passe", "Mot de passe incorrect ou clé invalide.")
                print(f"[ERROR] Mot de passe incorrect ou clé invalide: {str(ve)}")
                return
            except Exception as e:
                QMessageBox.critical(self, "Erreur de Clé", f"Impossible de charger la clé privée.\nErreur: {str(e)}")
                print(f"[ERROR] Impossible de charger la clé privée: {str(e)}")
                return

            # EXTRACTION DE LA CLÉ PUBLIQUE
            public_key_pem = self.private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8")

            print("[DEBUG] Clé publique extraite depuis la clé privée.")

            # Mettre à jour les affichages
            self.private_key_display.setPlainText(private_pem.decode("utf-8"))
            self.public_key_display.setPlainText(public_key_pem)

            # Demander si l'utilisateur veut enregistrer le chemin de la clé
            remember_key, ok = QInputDialog.getItem(
                self,
                "Sauvegarder la clé ?",
                "Voulez-vous sauvegarder cette clé pour éviter de la recharger à chaque fois ?",
                ["Oui", "Non"],
                0,
                False
            )
            if ok and remember_key == "Oui":
                save_config({"private_key_path": private_key_path})
                print(f"[DEBUG] Clé privée enregistrée dans {CONFIG_FILE}")

            QMessageBox.information(self, "Succès", "Clé privée et clé publique chargées avec succès !")

        except Exception as e:
            QMessageBox.critical(self, "Erreur de Clé", f"Impossible de charger la clé privée.\nErreur: {str(e)}")
            print(f"[ERROR] Impossible de charger la clé privée: {str(e)}")
    def forget_keys(self):
        """
        Oublier définitivement la clé privée enregistrée et effacer les traces.
        """
        # Effacer le fichier de configuration
        save_config({"private_key_path": ""})

        # Supprimer les références en mémoire
        self.private_key = None

        # Effacer l'affichage
        self.private_key_display.clear()
        self.public_key_display.clear()

        QMessageBox.information(self, "Clés oubliées", "La clé privée a été oubliée définitivement. Elle ne sera plus rechargée automatiquement.")
    def decrypt_file(self, file_path):
        """
        Déchiffrer un fichier avec la clé privée chargée ou générée.
        """
        if not self.private_key:
            QMessageBox.warning(
                self,
                "Clé Privée Manquante",
                "Veuillez d'abord générer ou charger une clé privée."
            )
            return

        # Lire le fichier chiffré
        try:
            with open(file_path, "rb") as f:
                encrypted_data = f.read()
        except Exception as e:
            QMessageBox.critical(self, "Erreur de Fichier", f"Impossible de lire le fichier.\nErreur: {str(e)}")
            return

        # **Get the correct RSA key size dynamically**
        rsa_key_size_bytes = self.private_key.key_size // 8  # Convert bits to bytes
        print(f"[DEBUG] RSA Key Size Detected: {self.private_key.key_size} bits ({rsa_key_size_bytes} bytes)")

        # Ensure the file has enough data
        if len(encrypted_data) < rsa_key_size_bytes + 16:
            QMessageBox.critical(self, "Erreur", "Fichier chiffré invalide ou corrompu.")
            return

        # **Extract encrypted AES key and IV based on RSA key size**
        try:
            encrypted_aes_key = encrypted_data[:rsa_key_size_bytes]  # Adjusted based on detected key size
            iv = encrypted_data[rsa_key_size_bytes:rsa_key_size_bytes + 16]  # IV is always 16 bytes
            actual_encrypted_data = encrypted_data[rsa_key_size_bytes + 16:]
        except Exception as e:
            QMessageBox.critical(
                self,
                "Erreur de Parsing",
                f"Impossible d'extraire les composants du fichier chiffré.\nErreur: {str(e)}"
            )
            return

        # **Decrypt AES Key using RSA**
        try:
            aes_key = self.private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print("[DEBUG] AES key successfully decrypted.")
        except Exception as e:
            QMessageBox.critical(
                self,
                "Erreur de Déchiffrement RSA",
                f"Impossible de déchiffrer la clé AES.\nErreur: {str(e)}"
            )
            return

        # **Decrypt file content using AES**
        try:
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.CFB(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(actual_encrypted_data) + decryptor.finalize()
            print("[DEBUG] File successfully decrypted.")
        except Exception as e:
            QMessageBox.critical(
                self,
                "Erreur de Déchiffrement AES",
                f"Impossible de déchiffrer les données.\nErreur: {str(e)}"
            )
            return

        # **Save the decrypted file**
        try:
            if file_path.endswith(".enc"):
                default_name = file_path[:-4]  # Remove `.enc` extension
            else:
                default_name = file_path + ".decrypted"

            decrypted_path, _ = QFileDialog.getSaveFileName(
                self,
                "Enregistrer le fichier déchiffré",
                default_name,
                "Tous les fichiers (*)"
            )
            if decrypted_path:
                with open(decrypted_path, "wb") as f:
                    f.write(decrypted_data)
                QMessageBox.information(
                    self,
                    "Succès",
                    f"Fichier déchiffré avec succès !\nChemin: {decrypted_path}"
                )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Erreur d'Enregistrement",
                f"Impossible d'enregistrer le fichier déchiffré.\nErreur: {str(e)}"
            )
class MainWindow(QMainWindow):
    """
    Fenêtre principale contenant les onglets Encryptor et Decryptor.
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Encryptor & Decryptor Application")
        self.setGeometry(100, 100, 800, 600)

        # Créer un QTabWidget
        self.tabs = QTabWidget()
        self.encryptor_tab = EncryptorTab()
        self.decryptor_tab = DecryptorTab()

        self.tabs.addTab(self.encryptor_tab, "Encryptor")
        self.tabs.addTab(self.decryptor_tab, "Decryptor")

        self.setCentralWidget(self.tabs)

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
