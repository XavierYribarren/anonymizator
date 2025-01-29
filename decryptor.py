import sys
import os
import json
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QPushButton,
    QVBoxLayout, QFileDialog, QMessageBox, QPlainTextEdit, QInputDialog
)
from PyQt6.QtCore import Qt
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


CONFIG_FILE = "decryptor_config.json"


def load_config():
    """ Charge la configuration enregistrée. """
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}


def save_config(data):
    """ Sauvegarde la configuration (chemin de la clé privée). """
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f)


def clear_config():
    """ Supprime la configuration enregistrée. """
    if os.path.exists(CONFIG_FILE):
        os.remove(CONFIG_FILE)


class DropLabel(QLabel):
    """
    Widget pour le drag-and-drop de fichiers.
    """
    def __init__(self, callback, parent=None):
        super().__init__(parent)
        self.callback = callback
        self.setAcceptDrops(True)
        self.setText("Glissez un fichier ici pour le déchiffrer.")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet("border: 3px dashed #0078D7; padding: 20px; font-size: 14pt;")
        self.setFixedHeight(200)  # 🔹 Zone de drop plus grande

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            self.callback(file_path)


class DecryptorApp(QMainWindow):
    """
    Application pour déchiffrer des fichiers avec une clé privée.
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Decryptor App")
        self.setGeometry(100, 100, 700, 500)

        layout = QVBoxLayout()

        # Boutons
        self.generate_keys_button = QPushButton("🔑 Générer une nouvelle paire de clés")
        self.generate_keys_button.clicked.connect(self.generate_keys)
        layout.addWidget(self.generate_keys_button)

        self.load_keys_button = QPushButton("📂 Charger une clé privée existante")
        self.load_keys_button.clicked.connect(self.load_keys)
        layout.addWidget(self.load_keys_button)

        self.forget_key_button = QPushButton("🗑️ Oublier la clé enregistrée")
        self.forget_key_button.clicked.connect(self.forget_keys)
        layout.addWidget(self.forget_key_button)

        self.toggle_key_button = QPushButton("👀 Afficher la clé privée")
        self.toggle_key_button.setEnabled(False)  # Désactivé tant qu'aucune clé n'est chargée
        self.toggle_key_button.clicked.connect(self.toggle_private_key_visibility)
        layout.addWidget(self.toggle_key_button)

        # Zones d'affichage des clés
        self.private_key_display = QPlainTextEdit()
        self.private_key_display.setPlaceholderText("Votre clé privée s'affichera ici.")
        self.private_key_display.setReadOnly(True)
        self.private_key_display.setFixedHeight(80)
        self.private_key_display.setVisible(False)  # 🔹 Caché par défaut

        self.public_key_display = QPlainTextEdit()
        self.public_key_display.setPlaceholderText("Votre clé publique s'affichera ici.")
        self.public_key_display.setReadOnly(True)
        self.public_key_display.setFixedHeight(100)

        layout.addWidget(QLabel("Clé Publique :"))
        layout.addWidget(self.public_key_display)

        # Zone de drop de fichier (plus grande)
        self.drop_label = DropLabel(callback=self.decrypt_file)
        layout.addWidget(self.drop_label)

        # Conteneur principal
        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        # Variable pour stocker la clé privée
        self.private_key = None
        self.private_key_visible = False  # 🔹 État de la visibilité

        # Vérifier si une clé est enregistrée
        self.check_for_saved_key()

    def check_for_saved_key(self):
        """ Vérifie si une clé privée est enregistrée et la charge automatiquement. """
        config = load_config()
        if "private_key_path" in config:
            self.load_keys(autoload=True)

    def generate_keys(self):
        """ Génère une nouvelle paire de clés RSA et l'affiche. """
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            public_key = private_key.public_key()

            # Sérialisation des clés
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode("utf-8")

            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8")

            # Mise à jour des affichages
            self.private_key_display.setPlainText(private_pem)
            self.public_key_display.setPlainText(public_pem)
            self.private_key = private_key
            self.toggle_key_button.setEnabled(True)

            # Sauvegarde optionnelle de la clé
            save_path, _ = QFileDialog.getSaveFileName(
                self, "Enregistrer la clé privée", "", "Clés privées (*.pem);;Tous les fichiers (*)"
            )
            if save_path:
                with open(save_path, "w") as f:
                    f.write(private_pem)
                QMessageBox.information(self, "Succès", f"Clé privée enregistrée dans {save_path}")
                save_config({"private_key_path": save_path})

        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Impossible de générer les clés.\nErreur: {str(e)}")

    def load_keys(self, autoload=False):
        """ Charge une clé privée existante. """
        config = load_config()
        if autoload and "private_key_path" in config:
            private_key_path = config["private_key_path"]
        else:
            private_key_path, _ = QFileDialog.getOpenFileName(
                self, "Charger une clé privée", "", "Clés privées (*.pem);;Tous les fichiers (*)"
            )

        if not private_key_path:
            return

        try:
            with open(private_key_path, "rb") as f:
                private_pem = f.read()

            self.private_key = serialization.load_pem_private_key(
                private_pem, password=None, backend=default_backend()
            )

            # Extraction de la clé publique
            public_pem = self.private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8")

            # Affichage mis à jour
            self.private_key_display.setPlainText(private_pem.decode("utf-8"))
            self.public_key_display.setPlainText(public_pem)
            self.toggle_key_button.setEnabled(True)

            # Sauvegarde du chemin de la clé privée
            save_config({"private_key_path": private_key_path})

        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Impossible de charger la clé privée.\nErreur: {str(e)}")

    def forget_keys(self):
        """ Oublie la clé enregistrée et efface les affichages. """
        clear_config()
        self.private_key = None
        self.private_key_display.clear()
        self.public_key_display.clear()
        self.private_key_display.setVisible(False)  # 🔹 Cachée après l'oubli
        self.toggle_key_button.setEnabled(False)
        QMessageBox.information(self, "Succès", "La clé enregistrée a été oubliée.")

    def toggle_private_key_visibility(self):
        """ Affiche ou masque la clé privée. """
        self.private_key_visible = not self.private_key_visible
        self.private_key_display.setVisible(self.private_key_visible)
        self.toggle_key_button.setText("🙈 Masquer la clé privée" if self.private_key_visible else "👀 Afficher la clé privée")

    def decrypt_file(self, file_path):
        """ Déchiffre un fichier avec la clé privée. """
        QMessageBox.information(self, "Déchiffrement", f"Déchiffrement simulé de : {file_path}")


def main():
    app = QApplication(sys.argv)
    window = DecryptorApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
