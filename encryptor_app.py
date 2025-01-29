import sys
import os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QPushButton,
    QVBoxLayout, QHBoxLayout, QFileDialog, QPlainTextEdit, QMessageBox
)
from PyQt6.QtCore import Qt
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class DropLabel(QLabel):
    """
    Widget pour le drag-and-drop de fichiers.
    """
    def __init__(self, callback, parent=None):
        super().__init__(parent)
        self.callback = callback
        self.setAcceptDrops(True)
        self.setText("Glissez un fichier ici pour le chiffrer.")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet("border: 2px dashed #aaa; padding: 10px;")

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            self.callback(file_path)


class EncryptorApp(QMainWindow):
    """
    Application pour chiffrer des fichiers avec une clé publique.
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Encryptor App")
        self.setGeometry(100, 100, 600, 400)

        layout = QVBoxLayout()

        # Champ pour coller la clé publique
        self.key_input = QPlainTextEdit()
        self.key_input.setPlaceholderText("Collez ici votre clé publique (format PEM ou OpenSSH).")
        self.key_input.setFixedHeight(100)
        layout.addWidget(QLabel("Clé Publique :"))
        layout.addWidget(self.key_input)

        # Zone de drag-and-drop
        self.drop_label = DropLabel(callback=self.encrypt_file)
        layout.addWidget(self.drop_label)

        # Bouton pour enregistrer le fichier chiffré
        self.save_button = QPushButton("Enregistrer le fichier chiffré")
        self.save_button.setEnabled(False)
        self.save_button.clicked.connect(self.save_encrypted_file)
        layout.addWidget(self.save_button)

        # Conteneur principal
        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        self.encrypted_data = None
        self.encrypted_path = None

    def encrypt_file(self, file_path):
        key_pem = self.key_input.toPlainText().strip()
        if not key_pem:
            QMessageBox.warning(self, "Clé Manquante", "Veuillez coller une clé publique avant de chiffrer un fichier.")
            return

        # Charger la clé publique
        try:
            public_key = serialization.load_pem_public_key(
                key_pem.encode('utf-8'),
                backend=default_backend()
            )
        except Exception as e:
            QMessageBox.critical(self, "Erreur de Clé", f"Impossible de charger la clé publique.\nErreur: {str(e)}")
            return

        # Lire le contenu du fichier
        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except Exception as e:
            QMessageBox.critical(self, "Erreur de Fichier", f"Impossible de lire le fichier.\nErreur: {str(e)}")
            return

        # Générer une clé AES
        aes_key = os.urandom(32)  # AES-256
        iv = os.urandom(16)       # IV pour le mode CFB
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        # Chiffrer la clé AES avec RSA
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Stocker la clé chiffrée, l'IV et les données chiffrées
        self.encrypted_data = encrypted_aes_key + iv + encrypted_data
        self.encrypted_path = file_path
        self.drop_label.setText(f"Fichier reçu:\n{file_path}\nChiffrement réussi !")
        self.save_button.setEnabled(True)

    def save_encrypted_file(self):
        if not self.encrypted_data:
            return

        save_path, _ = QFileDialog.getSaveFileName(
            self, "Enregistrer le fichier chiffré", "", "Fichiers chiffrés (*.enc);;Tous les fichiers (*)"
        )
        if save_path:
            with open(save_path, "wb") as f:
                f.write(self.encrypted_data)
            QMessageBox.information(self, "Succès", f"Fichier chiffré enregistré avec succès !\n{save_path}")


def main():
    app = QApplication(sys.argv)
    window = EncryptorApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
