import sys
import os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QPushButton,
    QVBoxLayout, QHBoxLayout, QTabWidget, QFileDialog, QMessageBox, QPlainTextEdit, QDialog
)
from PyQt6.QtCore import Qt
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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
    Utilise une approche hybride (AES + RSA) pour gérer de gros fichiers.
    """
    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QVBoxLayout()

        # Bouton pour Générer une Paire de Clés
        self.generate_keys_button = QPushButton("Générer Paire de Clés RSA")
        self.generate_keys_button.clicked.connect(self.generate_keys)
        layout.addWidget(self.generate_keys_button)

        # Affichage des Clés Générées
        keys_layout = QHBoxLayout()

        # Clé Privée
        private_key_layout = QVBoxLayout()
        private_key_label = QLabel("Clé Privée (à conserver secrète) :")
        self.private_key_display = QPlainTextEdit()
        self.private_key_display.setReadOnly(True)
        self.private_key_display.setPlaceholderText("Votre clé privée RSA s'affichera ici...")
        self.private_key_display.setFixedHeight(200)  # Ajustement de la taille
        private_key_layout.addWidget(private_key_label)
        private_key_layout.addWidget(self.private_key_display)
        keys_layout.addLayout(private_key_layout)

        # Clé Publique
        public_key_layout = QVBoxLayout()
        public_key_label = QLabel("Clé Publique (à partager) :")
        self.public_key_display = QPlainTextEdit()
        self.public_key_display.setReadOnly(True)
        self.public_key_display.setPlaceholderText("Votre clé publique RSA s'affichera ici...")
        self.public_key_display.setFixedHeight(200)  # Ajustement de la taille
        public_key_layout.addWidget(public_key_label)
        public_key_layout.addWidget(self.public_key_display)
        keys_layout.addLayout(public_key_layout)

        layout.addLayout(keys_layout)

        # Drag-and-Drop pour le Fichier à Déchiffrer
        self.drop_label = DropLabel(callback=self.decrypt_file)
        layout.addWidget(self.drop_label)

        self.setLayout(layout)

        # Variable pour stocker le chemin du fichier déchiffré
        self.decrypted_path = None

    def generate_keys(self):
        # Générer une paire de clés RSA
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

    def decrypt_file(self, file_path):
        # Demander à l'utilisateur de coller la clé privée
        key_dialog = KeyInputDialog()
        if key_dialog.exec():
            key_pem = key_dialog.get_key()
        else:
            QMessageBox.warning(
                self,
                "Clé Manquante",
                "Veuillez entrer une clé privée pour déchiffrer le fichier."
            )
            return

        if not key_pem:
            QMessageBox.warning(
                self,
                "Clé Manquante",
                "Veuillez entrer une clé privée valide pour déchiffrer le fichier."
            )
            return

        # Charger la clé privée
        try:
            private_key = serialization.load_pem_private_key(
                key_pem.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Erreur de Clé",
                f"Impossible de charger la clé privée.\nErreur: {str(e)}"
            )
            return

        # Lire le contenu du fichier chiffré
        try:
            with open(file_path, "rb") as f:
                encrypted_data = f.read()
        except Exception as e:
            QMessageBox.critical(
                self,
                "Erreur de Fichier",
                f"Impossible de lire le fichier.\nErreur: {str(e)}"
            )
            return

        # Extraire la clé AES chiffrée et l'IV
        try:
            encrypted_aes_key = encrypted_data[:256]  # RSA 2048 bits = 256 bytes
            iv = encrypted_data[256:272]             # IV de 16 bytes
            actual_encrypted_data = encrypted_data[272:]
        except Exception as e:
            QMessageBox.critical(
                self,
                "Erreur de Parsing",
                f"Impossible d'extraire les composants du fichier chiffré.\nErreur: {str(e)}"
            )
            return

        # Déchiffrer la clé AES avec la clé privée RSA
        try:
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Erreur de Déchiffrement RSA",
                f"Impossible de déchiffrer la clé AES.\nErreur: {str(e)}"
            )
            return

        # Déchiffrer les données avec la clé AES
        try:
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.CFB(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(actual_encrypted_data) + decryptor.finalize()
        except Exception as e:
            QMessageBox.critical(
                self,
                "Erreur de Déchiffrement AES",
                f"Impossible de déchiffrer les données.\nErreur: {str(e)}"
            )
            return

        # Demander où enregistrer le fichier déchiffré
        try:
            if file_path.endswith(".enc"):
                default_name = file_path[:-4]  # Retirer l'extension .enc
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
